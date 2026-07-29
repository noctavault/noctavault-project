//! Réseau Noctavault : maillage TCP à la Bitcoin (grosso modo), sans bloc
//! ni minage.
//!
//! - **Gossip par relais** : une enveloppe de transaction reçue, validée et
//!   nouvelle (rate-limit compris, voir `nv_chain::Ledger`) est re-propagée
//!   à tous les pairs connus. La déduplication est naturelle : une
//!   enveloppe déjà connue n'est ni ré-appliquée ni relayée, donc
//!   l'inondation s'arrête toute seule — chaque transaction s'applique
//!   directement dès réception, il n'y a pas de mempool ni de minage.
//! - **Sync** : échange complet de l'état connu (`GetTxs`/`Txs`) — cohérent
//!   avec la réplication totale déjà acceptée comme limite connue du
//!   projet. Une réponse par pair est limitée dans le temps pour éviter un
//!   DoS par spam de resynchronisation.
//! - Découverte : mDNS sur le LAN (`_noctavault._tcp.local.`) + PEX.
//!
//! Protocole : messages JSON préfixés par leur longueur (u32 big-endian).

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use nv_chain::{Envelope, Ledger, Tx};
use nv_core::identity::Identity;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const MAX_MSG: u32 = 256 * 1024 * 1024;
const MDNS_SERVICE: &str = "_noctavault._tcp.local.";
/// Une seule réponse à `GetTxs` par pair sur cette fenêtre, pour éviter un
/// pair qui spam la resynchronisation complète.
const GETTXS_COOLDOWN: Duration = Duration::from_secs(5);
/// Plafond de pairs connus par découverte (PEX/mDNS, jamais pour les pairs
/// configurés explicitement) : un pair distant contrôle entièrement le
/// contenu de `Msg::Peers` qu'il nous envoie (adresses arbitraires, pas de
/// corrélation avec un `GetPeers` qu'on aurait envoyé) — sans plafond, il
/// peut faire grossir notre `HashSet` sans limite et nous faire tenter des
/// connexions TCP vers des adresses de son choix (abus possible contre un
/// tiers).
const MAX_DISCOVERED_PEERS: usize = 1000;
/// Anti-Sybil best-effort : une identité est gratuite à créer (juste une
/// paire de clés), donc le rate-limit par identité de `nv-chain` seul ne
/// freine pas un attaquant qui en fabrique autant qu'il veut depuis une
/// même machine. On plafonne donc aussi le débit de `NewTx` *acceptés* par
/// IP source, indépendamment de l'identité signataire portée par
/// l'enveloppe. Contournable par qui dispose de plusieurs IP (VPN, botnet)
/// — pas une solution complète, mais ça retire l'intérêt d'un flood à
/// identités jetables depuis une seule source (à peine plus qu'une seule
/// identité honnête n'obtiendrait déjà).
const MAX_NEWTX_PER_IP_WINDOW: usize = 60;
const NEWTX_IP_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum NetError {
    #[error("E/S réseau : {0}")]
    Io(#[from] std::io::Error),
    #[error("format : {0}")]
    Format(String),
    #[error("message trop grand ({0} octets)")]
    TooBig(u32),
    #[error("mDNS : {0}")]
    Mdns(String),
    #[error("ledger : {0}")]
    Ledger(String),
}

#[derive(Serialize, Deserialize)]
pub enum Msg {
    /// Handshake informatif (aucun état de sync n'en dépend).
    Hello { tx_count: usize },
    /// Transaction soumise au réseau, appliquée directement et relayée.
    /// `Box` : `Envelope` est bien plus grosse que les autres variantes
    /// (elle embarque un `Tx`, potentiellement un `Manifest` entier).
    NewTx { envelope: Box<Envelope> },
    /// Demande l'ensemble des transactions connues du pair.
    GetTxs,
    Txs { envelopes: Vec<Envelope> },
    GetPeers,
    Peers { peers: Vec<String> },
}

pub async fn send_msg(stream: &mut TcpStream, msg: &Msg) -> Result<(), NetError> {
    let bytes = serde_json::to_vec(msg).map_err(|e| NetError::Format(e.to_string()))?;
    stream.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

pub async fn read_msg(stream: &mut TcpStream) -> Result<Msg, NetError> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MSG {
        return Err(NetError::TooBig(len));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(|e| NetError::Format(e.to_string()))
}

/// Nœud réseau : écoute, gossip et se synchronise autour d'un `Ledger`
/// partagé. L'ensemble des pairs évolue (config, mDNS, PEX).
#[derive(Clone)]
pub struct Node {
    pub ledger: Arc<Mutex<Ledger>>,
    pub peers: Arc<Mutex<HashSet<SocketAddr>>>,
    last_txs_reply: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    newtx_rate: Arc<Mutex<HashMap<IpAddr, VecDeque<Instant>>>>,
}

impl Node {
    pub fn new(ledger: Ledger, peers: impl IntoIterator<Item = SocketAddr>) -> Self {
        Node {
            ledger: Arc::new(Mutex::new(ledger)),
            peers: Arc::new(Mutex::new(peers.into_iter().collect())),
            last_txs_reply: Arc::new(Mutex::new(HashMap::new())),
            newtx_rate: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// `true` si on doit encore accepter un `NewTx` de cette IP source sur
    /// la fenêtre courante (voir `MAX_NEWTX_PER_IP_WINDOW`). Compte
    /// uniquement les enveloppes qu'on tente réellement d'appliquer,
    /// indépendamment de l'identité qui les signe.
    async fn allow_newtx_from(&self, ip: IpAddr) -> bool {
        let mut map = self.newtx_rate.lock().await;
        let now = Instant::now();
        let window = map.entry(ip).or_default();
        while window.front().is_some_and(|t| now.duration_since(*t) >= NEWTX_IP_WINDOW) {
            window.pop_front();
        }
        if window.len() >= MAX_NEWTX_PER_IP_WINDOW {
            return false;
        }
        window.push_back(now);
        true
    }

    pub async fn add_peer(&self, addr: SocketAddr) -> bool {
        self.peers.lock().await.insert(addr)
    }

    /// Point d'entrée unique pour les pairs *découverts* (mDNS, PEX) —
    /// plafonnés à `MAX_DISCOVERED_PEERS` au total, contrairement à
    /// `add_peer` (pairs configurés explicitement par l'utilisateur,
    /// volontairement non plafonnés). Centraliser ici évite qu'un futur
    /// point d'entrée de découverte réintroduise le même risque de
    /// croissance sans limite en oubliant le plafond.
    async fn merge_discovered_peers(&self, addrs: impl IntoIterator<Item = SocketAddr>) {
        let mut set = self.peers.lock().await;
        for addr in addrs {
            if set.len() >= MAX_DISCOVERED_PEERS {
                break;
            }
            set.insert(addr);
        }
    }

    pub async fn peer_list(&self) -> Vec<SocketAddr> {
        self.peers.lock().await.iter().copied().collect()
    }

    /// Démarre l'écoute. Retourne l'adresse réellement liée.
    pub async fn listen(&self, addr: SocketAddr) -> Result<SocketAddr, NetError> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let node = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, peer_addr)) = listener.accept().await else { break };
                let node = node.clone();
                tokio::spawn(async move {
                    let _ = handle_conn(stream, peer_addr, node).await;
                });
            }
        });
        Ok(local)
    }

    /// Annonce ce nœud en mDNS et absorbe les nœuds découverts sur le LAN.
    /// Retourne le démon à garder en vie.
    pub fn start_mdns(&self, port: u16) -> Result<ServiceDaemon, NetError> {
        let daemon = ServiceDaemon::new().map_err(|e| NetError::Mdns(e.to_string()))?;
        let instance = format!("nv-{}", std::process::id());
        let host = format!("{instance}.local.");
        let info = ServiceInfo::new(MDNS_SERVICE, &instance, &host, (), port, None)
            .map_err(|e| NetError::Mdns(e.to_string()))?
            .enable_addr_auto();
        daemon
            .register(info)
            .map_err(|e| NetError::Mdns(e.to_string()))?;

        let receiver = daemon
            .browse(MDNS_SERVICE)
            .map_err(|e| NetError::Mdns(e.to_string()))?;
        let node = self.clone();
        let me = instance;
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                if let ServiceEvent::ServiceResolved(info) = event {
                    if info.get_fullname().starts_with(&me) {
                        continue; // soi-même
                    }
                    let addrs =
                        info.get_addresses().iter().map(|ip| SocketAddr::new(*ip, info.get_port()));
                    node.merge_discovered_peers(addrs).await;
                }
            }
        });
        Ok(daemon)
    }

    async fn send_to_all(&self, msg: &Msg) -> usize {
        let mut sent = 0;
        for peer in self.peer_list().await {
            if let Ok(mut stream) = TcpStream::connect(peer).await {
                if send_msg(&mut stream, msg).await.is_ok() {
                    sent += 1;
                }
            }
        }
        sent
    }

    /// Diffuse une enveloppe à tous les pairs connus (qui la relaieront).
    /// Prend `envelope` par valeur : elle peut peser jusqu'à ~1,4 Mo en
    /// base64 pour un chunk de 1 MiB (voire un `Manifest` entier) — les
    /// appelants ont tous déjà fini de s'en servir à ce point (après leur
    /// propre clone pour `Ledger::submit`), autant la déplacer plutôt que
    /// la cloner une deuxième fois sur le chemin chaud du relais gossip.
    pub async fn broadcast_envelope(&self, envelope: Envelope) -> usize {
        self.send_to_all(&Msg::NewTx { envelope: Box::new(envelope) }).await
    }

    /// Signe `tx` au nom de `identity`, l'applique localement (validation +
    /// rate-limit inclus) et la diffuse si elle est nouvelle. Retourne le
    /// nombre de pairs touchés (0 si déjà connue ou rejetée).
    pub async fn submit_tx(&self, tx: Tx, identity: &Identity) -> Result<usize, NetError> {
        let envelope = Envelope::new(tx, identity).map_err(|e| NetError::Ledger(e.to_string()))?;
        let applied = {
            let mut ledger = self.ledger.lock().await;
            // Ledger::submit fait de l'E/S disque + vérif de signature :
            // pas bloquant au point de nécessiter systématiquement
            // block_in_place (plus de verrou de fichier ni de PoW), mais on
            // le garde par prudence/cohérence avec le reste du code réseau.
            tokio::task::block_in_place(|| ledger.submit(envelope.clone()))
        };
        match applied {
            Ok(true) => Ok(self.broadcast_envelope(envelope).await),
            Ok(false) => Ok(0),
            Err(e) => Err(NetError::Ledger(e.to_string())),
        }
    }

    /// Une passe de synchronisation : PEX + échange complet des
    /// transactions connues avec chaque pair.
    pub async fn sync_once(&self) -> Result<bool, NetError> {
        let mut updated = false;
        for peer in self.peer_list().await {
            let Ok(mut stream) = TcpStream::connect(peer).await else { continue };

            // Échange de pairs : on apprend les pairs de nos pairs.
            if send_msg(&mut stream, &Msg::GetPeers).await.is_ok() {
                if let Ok(Msg::Peers { peers }) = read_msg(&mut stream).await {
                    let addrs = peers.iter().filter_map(|p| p.parse::<SocketAddr>().ok());
                    self.merge_discovered_peers(addrs).await;
                }
            }

            if send_msg(&mut stream, &Msg::GetTxs).await.is_err() {
                continue;
            }
            let Ok(Msg::Txs { envelopes }) = read_msg(&mut stream).await else { continue };
            if envelopes.is_empty() {
                continue;
            }
            let mut ledger = self.ledger.lock().await;
            let applied_any = tokio::task::block_in_place(|| {
                let mut any = false;
                for env in envelopes {
                    if ledger.submit(env).unwrap_or(false) {
                        any = true;
                    }
                }
                any
            });
            if applied_any {
                updated = true;
            }
        }
        Ok(updated)
    }
}

async fn handle_conn(mut stream: TcpStream, peer_addr: SocketAddr, node: Node) -> Result<(), NetError> {
    loop {
        let msg = read_msg(&mut stream).await?;
        match msg {
            Msg::Hello { .. } => {
                let tx_count = node.ledger.lock().await.tx_count();
                send_msg(&mut stream, &Msg::Hello { tx_count }).await?;
            }
            Msg::NewTx { envelope } => {
                if !node.allow_newtx_from(peer_addr.ip()).await {
                    continue;
                }
                // Ledger::submit valide signature + tx + rate-limit ; ne
                // relaie que si vraiment nouvelle (fin de l'inondation).
                let applied = {
                    let mut ledger = node.ledger.lock().await;
                    tokio::task::block_in_place(|| ledger.submit((*envelope).clone()))
                };
                if applied.unwrap_or(false) {
                    let node = node.clone();
                    tokio::spawn(async move {
                        node.broadcast_envelope(*envelope).await;
                    });
                }
            }
            Msg::GetTxs => {
                let mut cooldowns = node.last_txs_reply.lock().await;
                let now = Instant::now();
                let allowed = cooldowns
                    .get(&peer_addr)
                    .is_none_or(|last| now.duration_since(*last) >= GETTXS_COOLDOWN);
                if !allowed {
                    send_msg(&mut stream, &Msg::Txs { envelopes: Vec::new() }).await?;
                    continue;
                }
                cooldowns.insert(peer_addr, now);
                drop(cooldowns);
                let ledger = node.ledger.lock().await;
                let envelopes = ledger.all_envelopes().unwrap_or_default();
                drop(ledger);
                send_msg(&mut stream, &Msg::Txs { envelopes }).await?;
            }
            Msg::Txs { envelopes } => {
                // Même plafond par IP que `NewTx` : un pair pourrait sinon
                // contourner le rate-limit en glissant ses enveloppes dans
                // une réponse `Txs` plutôt qu'en `NewTx` individuels.
                for env in envelopes {
                    if !node.allow_newtx_from(peer_addr.ip()).await {
                        break;
                    }
                    let mut ledger = node.ledger.lock().await;
                    let _ = tokio::task::block_in_place(|| ledger.submit(env));
                }
            }
            Msg::GetPeers => {
                let peers = node
                    .peer_list()
                    .await
                    .iter()
                    .map(|p| p.to_string())
                    .collect();
                send_msg(&mut stream, &Msg::Peers { peers }).await?;
            }
            Msg::Peers { peers } => {
                let addrs = peers.iter().filter_map(|p| p.parse::<SocketAddr>().ok());
                node.merge_discovered_peers(addrs).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nv_core::identity::Identity;

    async fn spawn_node(dir: &std::path::Path, peers: Vec<SocketAddr>) -> (Node, SocketAddr) {
        let ledger = Ledger::open(dir).unwrap();
        let node = Node::new(ledger, peers);
        let addr = node.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        (node, addr)
    }

    fn put_chunk_tx(data: &[u8]) -> Tx {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        Tx::PutChunk { hash: blake3::hash(data).to_hex().to_string(), data_b64: B64.encode(data) }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn deux_noeuds_se_synchronisent() {
        let id = Identity::generate();
        let da = tempfile::tempdir().unwrap();
        let db = tempfile::tempdir().unwrap();

        let mut ledger_a = Ledger::open(da.path()).unwrap();
        ledger_a.submit(nv_chain::Envelope::new(put_chunk_tx(b"un"), &id).unwrap()).unwrap();
        ledger_a.submit(nv_chain::Envelope::new(put_chunk_tx(b"deux"), &id).unwrap()).unwrap();
        let node_a = Node::new(ledger_a, []);
        let addr_a = node_a.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

        let ledger_b = Ledger::open(db.path()).unwrap();
        let node_b = Node::new(ledger_b, [addr_a]);
        assert!(node_b.sync_once().await.unwrap());
        assert_eq!(node_b.ledger.lock().await.tx_count(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn relais_gossip_en_chaine() {
        // A -> B -> C : C n'est pas pair de A, la tx doit lui parvenir
        // par relais via B (comme Bitcoin).
        let id = Identity::generate();
        let d = |_: u8| tempfile::tempdir().unwrap();
        let (dc, db_, da) = (d(0), d(1), d(2));

        let (node_c, addr_c) = spawn_node(dc.path(), vec![]).await;
        let (_node_b, addr_b) = spawn_node(db_.path(), vec![addr_c]).await;

        let ledger_a = Ledger::open(da.path()).unwrap();
        let node_a = Node::new(ledger_a, [addr_b]);
        node_a.submit_tx(put_chunk_tx(b"relais"), &id).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(node_c.ledger.lock().await.tx_count(), 1, "la tx doit être relayée jusqu'à C");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn soumission_directe_sans_minage() {
        // Une tx soumise s'applique immédiatement, sans étape de minage.
        let emetteur_id = Identity::generate();
        let dm = tempfile::tempdir().unwrap();
        let de = tempfile::tempdir().unwrap();

        let (node_recepteur, addr_recepteur) = spawn_node(dm.path(), vec![]).await;
        let (node_emetteur, _addr) = spawn_node(de.path(), vec![addr_recepteur]).await;

        let sent = node_emetteur.submit_tx(put_chunk_tx(b"direct"), &emetteur_id).await.unwrap();
        assert_eq!(sent, 1, "diffusée à l'unique pair connu");
        assert_eq!(node_emetteur.ledger.lock().await.tx_count(), 1, "appliquée localement tout de suite");

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(node_recepteur.ledger.lock().await.tx_count(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn echange_de_pairs() {
        let da = tempfile::tempdir().unwrap();
        let db = tempfile::tempdir().unwrap();
        let id = Identity::generate();

        let mut ledger_a = Ledger::open(da.path()).unwrap();
        ledger_a.submit(nv_chain::Envelope::new(put_chunk_tx(b"a"), &id).unwrap()).unwrap();
        let node_a = Node::new(ledger_a, ["10.9.8.7:7777".parse().unwrap()]);
        let addr_a = node_a.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

        let ledger_b = Ledger::open(db.path()).unwrap();
        let node_b = Node::new(ledger_b, [addr_a]);
        node_b.sync_once().await.unwrap();
        assert!(node_b
            .peer_list()
            .await
            .contains(&"10.9.8.7:7777".parse().unwrap()));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pex_plafonne_le_nombre_de_pairs_decouverts() {
        // Un pair quelconque (réseau public) peut nous envoyer un
        // `Msg::Peers` arbitrairement gros, non sollicité : sans plafond,
        // notre `HashSet` de pairs grossirait sans limite et notre démon
        // tenterait de se connecter à toutes ces adresses.
        let d = tempfile::tempdir().unwrap();
        let (node, addr) = spawn_node(d.path(), vec![]).await;

        let n = MAX_DISCOVERED_PEERS + 500;
        let fake_peers: Vec<String> =
            (0..n).map(|i| format!("127.0.0.1:{}", 20000 + i)).collect();

        let mut stream = TcpStream::connect(addr).await.unwrap();
        send_msg(&mut stream, &Msg::Peers { peers: fake_peers }).await.unwrap();
        // Laisse `handle_conn` traiter le message avant de vérifier.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        assert_eq!(node.peers.lock().await.len(), MAX_DISCOVERED_PEERS);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn newtx_plafonne_par_ip_meme_avec_identites_differentes() {
        // Une identité est gratuite à créer (juste une paire de clés) :
        // sans plafond par IP source, un attaquant qui en fabrique une
        // par transaction contournerait entièrement le rate-limit par
        // identité de nv-chain (Sybil).
        let d = tempfile::tempdir().unwrap();
        let (node, addr) = spawn_node(d.path(), vec![]).await;

        let n = MAX_NEWTX_PER_IP_WINDOW + 20;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        for i in 0..n {
            let id = Identity::generate(); // identité différente à chaque tour
            let tx = put_chunk_tx(format!("chunk-{i}").as_bytes());
            let envelope = Envelope::new(tx, &id).unwrap();
            send_msg(&mut stream, &Msg::NewTx { envelope: Box::new(envelope) })
                .await
                .unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let applied = node.ledger.lock().await.tx_count();
        assert_eq!(applied, MAX_NEWTX_PER_IP_WINDOW);
    }
}
