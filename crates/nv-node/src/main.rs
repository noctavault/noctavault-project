use anyhow::Result;
use clap::{Parser, Subcommand};
use nv_node::Home;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "nv-node", about = "Nœud Noctavault : cloud chiffré post-quantique")]
struct Cli {
    /// Répertoire de données (défaut : ~/.noctavault)
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Crée l'identité post-quantique (ML-KEM-1024 + ML-DSA-65)
    Init,
    /// Chiffre un fichier, écrit le .nvault, l'insère dans le ledger et le diffuse
    Add {
        file: PathBuf,
        /// Portefeuilles publics .nvid des destinataires supplémentaires
        #[arg(long, value_delimiter = ',')]
        to: Vec<PathBuf>,
    },
    /// Reconstruit un fichier depuis son .nvault (nécessite la clé privée)
    Get {
        manifest: PathBuf,
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Liste les fichiers publiés dans le ledger local
    Ls,
    /// État du nœud
    Status,
    /// Révoque un de nos fichiers : purge des chunks chez tous les nœuds
    Revoke { file_id: String },
    /// Exporte le portefeuille public (.nvid) à donner aux contacts
    Id {
        /// Fichier de sortie (défaut : affiche sur la sortie standard)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Lance le démon : écoute, synchronisation périodique
    Daemon {
        /// Adresse d'écoute (défaut : config ou 0.0.0.0:7777)
        #[arg(long)]
        listen: Option<String>,
        /// Pairs supplémentaires host:port, séparés par des virgules
        #[arg(long, value_delimiter = ',')]
        peers: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let home = Home::new(cli.home)?;

    match cli.cmd {
        Cmd::Init => {
            let (id, created) = home.init_identity()?;
            if created {
                println!("Identité créée : {}", id.id());
                println!("Clés : {}", home.identity_path().display());
            } else {
                println!("Identité existante : {}", id.id());
            }
        }
        Cmd::Add { file, to } => {
            let recipients: Vec<_> = to
                .iter()
                .map(|p| nv_core::identity::PublicIdentity::load(p))
                .collect::<Result<_, _>>()?;
            let outcome = nv_node::add_file(&home, &file, &recipients).await?;
            if !recipients.is_empty() {
                println!(
                    "Partagé avec : {}",
                    recipients.iter().map(|r| r.id()).collect::<Vec<_>>().join(", ")
                );
            }
            println!("Fichier chiffré : {} chunks", outcome.n_chunks);
            println!("Manifeste : {}", outcome.manifest_path.display());
            println!("Diffusé à {} pair(s)", outcome.peers_notified);
        }
        Cmd::Get { manifest, out } => {
            let path = nv_node::get_file(&home, &manifest, out)?;
            println!("Fichier reconstruit : {}", path.display());
        }
        Cmd::Ls => {
            let manifests = nv_node::list_files(&home)?;
            if manifests.is_empty() {
                println!("(aucun fichier dans le ledger)");
            }
            for m in manifests {
                println!(
                    "{}  {:>10} o  {} chunks  propriétaire {}  {}",
                    &m.file_id[..16],
                    m.size,
                    m.chunks.len(),
                    m.owner.id(),
                    m.name
                );
            }
        }
        Cmd::Revoke { file_id } => {
            let tx_count = nv_node::revoke_file(&home, &file_id).await?;
            println!("Fichier révoqué, chunks purgés. Transactions connues : {tx_count}");
        }
        Cmd::Id { out } => {
            let identity = home.identity()?;
            match out {
                Some(p) => {
                    identity.public.save(&p)?;
                    println!("Portefeuille public exporté : {}", p.display());
                }
                None => print!("{}", identity.public.to_text()?),
            }
        }
        Cmd::Status => {
            let ledger = home.open_ledger()?;
            println!("Répertoire : {}", home.dir.display());
            println!("Transactions connues : {}", ledger.tx_count());
            println!("Fichiers publiés : {}", ledger.manifests().len());
            println!("Pairs : {:?}", home.peers()?);
        }
        Cmd::Daemon { listen, peers } => {
            let mut config = home.load_config()?;
            if !peers.is_empty() {
                config.peers = peers;
            }
            if let Some(l) = listen {
                config.listen = Some(l);
            }
            home.save_config(&config)?;
            let listen_addr: std::net::SocketAddr = config
                .listen
                .clone()
                .unwrap_or_else(|| "0.0.0.0:7777".into())
                .parse()?;

            let ledger = home.open_ledger()?;
            let resolved_peers = home.peers()?;
            let node = nv_net::Node::new(ledger, resolved_peers.clone());
            let bound = node.listen(listen_addr).await?;
            println!("Nœud à l'écoute sur {bound}");
            println!("Pairs : {resolved_peers:?}");
            // Découverte automatique des nœuds du réseau local.
            let _mdns = match node.start_mdns(bound.port()) {
                Ok(d) => {
                    println!("mDNS actif : découverte auto sur le LAN");
                    Some(d)
                }
                Err(e) => {
                    eprintln!("mDNS indisponible : {e}");
                    None
                }
            };

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                        // Rattrapage des enveloppes écrites directement sur
                        // le disque par un autre processus (ex : `nv-node
                        // add` lancé en CLI sur le même --home) : les
                        // enveloppes sont adressées par contenu, donc plus
                        // besoin de verrou inter-processus, juste relire le
                        // dossier `txs/` pour rattraper les nouvelles.
                        let refreshed = {
                            let mut ledger = node.ledger.lock().await;
                            tokio::task::block_in_place(|| ledger.refresh())
                        };
                        match refreshed {
                            Ok(true) => {
                                let n = node.ledger.lock().await.tx_count();
                                println!("Ledger rattrapé (écriture locale d'un autre processus), {n} transactions connues");
                            }
                            Ok(false) => {}
                            Err(e) => eprintln!("rattrapage local : {e}"),
                        }
                        match node.sync_once().await {
                            Ok(true) => {
                                let n = node.ledger.lock().await.tx_count();
                                println!("Ledger synchronisé, {n} transactions connues");
                            }
                            Ok(false) => {}
                            Err(e) => eprintln!("sync : {e}"),
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        println!("Arrêt du nœud.");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}
