//! Logique de nœud partagée entre le CLI et l'application GUI.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use nv_chain::{Envelope, Ledger, Tx};
use nv_core::identity::Identity;
use nv_core::{vault, Manifest};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

/// Nœuds d'amorçage publics : point d'entrée pour un tout nouvel arrivant
/// qui ne connaît encore personne sur le réseau (pas sur le même LAN, donc
/// mDNS ne peut pas l'aider). Utilisés uniquement si aucun pair n'est déjà
/// configuré — voir `Home::peers()`.
pub const DEFAULT_BOOTSTRAP_PEERS: &[&str] = &["noctavault.duckdns.org:7777"];

#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    /// Adresse d'écoute du démon, ex. "0.0.0.0:7777".
    pub listen: Option<String>,
    /// Pairs connus, ex. ["192.168.1.10:7777"].
    #[serde(default)]
    pub peers: Vec<String>,
}

/// Répertoire de données (~/.noctavault par défaut, surchargé par --home).
pub struct Home {
    pub dir: PathBuf,
}

impl Home {
    pub fn new(dir: Option<PathBuf>) -> Result<Self> {
        let dir = match dir {
            Some(d) => d,
            None => dirs_home()?.join(".noctavault"),
        };
        std::fs::create_dir_all(&dir)?;
        Ok(Home { dir })
    }

    pub fn identity_path(&self) -> PathBuf {
        self.dir.join("identity.nvkey")
    }

    pub fn ledger_dir(&self) -> PathBuf {
        self.dir.join("chain")
    }

    pub fn config_path(&self) -> PathBuf {
        self.dir.join("config.json")
    }

    pub fn load_config(&self) -> Result<Config> {
        let p = self.config_path();
        if !p.exists() {
            return Ok(Config::default());
        }
        Ok(serde_json::from_str(&std::fs::read_to_string(p)?)?)
    }

    pub fn save_config(&self, config: &Config) -> Result<()> {
        std::fs::write(self.config_path(), serde_json::to_string_pretty(config)?)?;
        Ok(())
    }

    /// Crée l'identité si absente ; retourne (identité, créée ?).
    pub fn init_identity(&self) -> Result<(Identity, bool)> {
        let p = self.identity_path();
        if p.exists() {
            Ok((Identity::load(&p)?, false))
        } else {
            let id = Identity::generate();
            id.save(&p)?;
            Ok((id, true))
        }
    }

    pub fn identity(&self) -> Result<Identity> {
        let p = self.identity_path();
        if !p.exists() {
            bail!("aucune identité : lancer d'abord `nv-node init`");
        }
        Ok(Identity::load(&p)?)
    }

    pub fn open_ledger(&self) -> Result<Ledger> {
        Ok(Ledger::open(&self.ledger_dir())?)
    }

    /// Pairs configurés, ou à défaut les nœuds d'amorçage publics : un tout
    /// nouvel arrivant n'a sinon aucun moyen de rejoindre le réseau s'il ne
    /// connaît déjà quelqu'un (mDNS ne l'aide que sur le même LAN).
    pub fn peers(&self) -> Result<Vec<SocketAddr>> {
        let config = self.load_config()?;
        if config.peers.is_empty() {
            return Ok(resolve_bootstrap_peers());
        }
        config
            .peers
            .iter()
            .map(|p| p.parse().with_context(|| format!("pair invalide : {p}")))
            .collect()
    }
}

/// Résout les nœuds d'amorçage (nom d'hôte, pas juste IP littérale) ;
/// ignore silencieusement ceux injoignables (DNS indisponible hors ligne,
/// nœud d'amorçage temporairement down) plutôt que de faire échouer le
/// démarrage pour autant.
fn resolve_bootstrap_peers() -> Vec<SocketAddr> {
    resolve_hosts(DEFAULT_BOOTSTRAP_PEERS)
}

fn resolve_hosts(hosts: &[&str]) -> Vec<SocketAddr> {
    hosts
        .iter()
        .filter_map(|s| s.to_socket_addrs().ok())
        .flatten()
        .collect()
}

fn dirs_home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("variable HOME absente")
}

/// Résultat d'un ajout de fichier.
pub struct AddOutcome {
    pub manifest_path: PathBuf,
    pub file_id: String,
    pub n_chunks: usize,
    pub peers_notified: usize,
}

/// Chiffre `data` pour `identity`, insère chunks + manifeste dans `ledger`
/// (directement, sans minage) et retourne (manifeste, enveloppes signées
/// pour diffusion). Cœur partagé CLI / GUI.
pub fn add_to_ledger(
    ledger: &mut Ledger,
    identity: &Identity,
    data: &[u8],
    name: &str,
    to: &[nv_core::identity::PublicIdentity],
    prev_version: Option<String>,
) -> Result<(Manifest, Vec<Envelope>)> {
    let enc = vault::encrypt_for(data, name, identity, to, prev_version)?;
    let mut envelopes = Vec::with_capacity(enc.chunks.len() + 1);
    for (hash, data) in &enc.chunks {
        let tx = Tx::PutChunk { hash: hash.clone(), data_b64: B64.encode(data) };
        let envelope = Envelope::new(tx, identity)?;
        ledger.submit(envelope.clone())?;
        envelopes.push(envelope);
    }
    let manifest_tx = Tx::PublishManifest { manifest: enc.manifest.clone() };
    let envelope = Envelope::new(manifest_tx, identity)?;
    ledger.submit(envelope.clone())?;
    envelopes.push(envelope);
    Ok((enc.manifest, envelopes))
}

/// Chemin du manifeste écrit à côté du fichier d'origine.
pub fn manifest_path_for(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}nvault",
        path.extension()
            .map(|e| format!("{}.", e.to_string_lossy()))
            .unwrap_or_default()
    ))
}

/// Chiffre `path`, écrit le .nvault à côté, insère le tout dans le ledger
/// local (application directe, sans minage) et diffuse aux pairs. `to` =
/// portefeuilles publics destinataires supplémentaires.
pub async fn add_file(
    home: &Home,
    path: &Path,
    to: &[nv_core::identity::PublicIdentity],
) -> Result<AddOutcome> {
    let identity = home.identity()?;
    let data = std::fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    let name = path
        .file_name()
        .context("nom de fichier invalide")?
        .to_string_lossy()
        .to_string();

    let mut ledger = home.open_ledger()?;
    // Nouvelle version automatique si un fichier du même nom (même
    // propriétaire) existe déjà dans le ledger.
    let prev_version = ledger
        .manifests()
        .iter()
        .rev()
        .find(|m| m.name == name && m.owner.id() == identity.id())
        .map(|m| m.file_id.clone());
    // Ledger::submit fait de l'E/S disque + vérif de signature : on garde
    // block_in_place par prudence, comme partout ailleurs dans le code
    // réseau/nœud (plus de PoW ni de verrou de fichier à attendre, mais ça
    // évite de geler le driver tokio pour le broadcast juste après).
    let (manifest, envelopes) = tokio::task::block_in_place(|| {
        add_to_ledger(&mut ledger, &identity, &data, &name, to, prev_version)
    })?;
    let manifest_path = manifest_path_for(path);
    manifest.save(&manifest_path)?;

    let peers = home.peers()?;
    let node = nv_net::Node::new(ledger, peers.clone());
    for envelope in envelopes {
        node.broadcast_envelope(envelope).await;
    }

    Ok(AddOutcome {
        manifest_path,
        file_id: manifest.file_id,
        n_chunks: manifest.chunks.len(),
        peers_notified: peers.len(),
    })
}

/// `manifest.name` est choisi par l'émetteur du fichier (auto-signé, donc
/// jamais garanti sûr comme composant de chemin) — quiconque a notre
/// `.nvid` peut nous envoyer un manifeste avec `name = "../../.bashrc"` ou
/// un chemin absolu. On n'en garde que le composant final, comme le ferait
/// n'importe quel navigateur pour un nom de fichier téléchargé.
pub fn safe_out_name(manifest: &Manifest) -> String {
    Path::new(&manifest.name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("fichier-{}", &manifest.file_id[..16]))
}

/// Reconstruit un fichier depuis un manifeste .nvault et le ledger local.
pub fn get_file(home: &Home, manifest_path: &Path, out: Option<PathBuf>) -> Result<PathBuf> {
    let identity = home.identity()?;
    let manifest = Manifest::load(manifest_path)?;
    let ledger = home.open_ledger()?;
    let data = vault::decrypt(&manifest, &identity, |h| ledger.get_chunk(h))?;
    let out = out.unwrap_or_else(|| {
        manifest_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(safe_out_name(&manifest))
    });
    std::fs::write(&out, data)?;
    Ok(out)
}

/// Liste les manifestes présents dans le ledger local.
pub fn list_files(home: &Home) -> Result<Vec<Manifest>> {
    Ok(home.open_ledger()?.manifests().to_vec())
}

/// Révoque un fichier (le nôtre) : tx signée, appliquée directement,
/// diffusée. Retourne le nombre de transactions connues après révocation.
pub async fn revoke_file(home: &Home, file_id: &str) -> Result<usize> {
    let identity = home.identity()?;
    let mut ledger = home.open_ledger()?;
    let full_id = ledger
        .manifests()
        .iter()
        .find(|m| m.file_id.starts_with(file_id))
        .map(|m| m.file_id.clone())
        .with_context(|| format!("fichier {file_id} introuvable dans le ledger"))?;
    let tx = nv_chain::make_revoke(&full_id, &identity)?;
    let envelope = Envelope::new(tx, &identity)?;
    tokio::task::block_in_place(|| ledger.submit(envelope.clone()))?;
    let tx_count = ledger.tx_count();
    let node = nv_net::Node::new(ledger, home.peers()?);
    node.broadcast_envelope(envelope).await;
    Ok(tx_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifeste_nomme(name: &str) -> Manifest {
        Manifest {
            version: 1,
            file_id: "a".repeat(64),
            name: name.to_string(),
            size: 0,
            created: 0,
            compression: "none".into(),
            prev_version: None,
            owner: nv_core::identity::Identity::generate().public,
            recipients: vec![],
            chunks: vec![],
            signature: String::new(),
        }
    }

    #[test]
    fn safe_out_name_nom_normal_inchange() {
        assert_eq!(safe_out_name(&manifeste_nomme("rapport.pdf")), "rapport.pdf");
    }

    // `manifest.name` vient de l'émetteur (auto-signé, jamais validé pour
    // la forme) : quiconque a notre `.nvid` peut nous envoyer un manifeste
    // avec un `name` malveillant pour écrire hors du répertoire attendu.
    #[test]
    fn safe_out_name_traversee_de_chemin_neutralisee() {
        let n = safe_out_name(&manifeste_nomme("../../.bashrc"));
        assert_eq!(n, ".bashrc");
        assert!(!n.contains(".."));
    }

    #[test]
    fn safe_out_name_chemin_absolu_neutralise() {
        let n = safe_out_name(&manifeste_nomme("/etc/cron.d/evil"));
        assert_eq!(n, "evil");
        assert!(!n.starts_with('/'));
    }

    #[test]
    fn safe_out_name_vide_ou_parent_seul_a_un_fallback() {
        for name in ["", "..", ".", "../.."] {
            let n = safe_out_name(&manifeste_nomme(name));
            assert!(!n.is_empty() && !n.contains(".."), "name={name:?} -> {n:?}");
        }
    }

    // `localhost` se résout via /etc/hosts, sans dépendre du réseau : le
    // test reste fiable même hors ligne (contrairement au vrai nœud
    // d'amorçage DuckDNS, résolu par DNS public).
    #[test]
    fn resolve_hosts_nom_valide_est_resolu() {
        let addrs = resolve_hosts(&["localhost:7777"]);
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.port() == 7777));
    }

    #[test]
    fn resolve_hosts_nom_invalide_est_ignore_silencieusement() {
        let addrs = resolve_hosts(&["ceci-nexiste-pas.invalide:7777"]);
        assert!(addrs.is_empty());
    }
}
