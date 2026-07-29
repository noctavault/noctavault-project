//! Ledger Noctavault : journal de transactions signées, répliqué
//! intégralement sur chaque nœud, sans notion de bloc ni de minage.
//!
//! Chaque transaction (`Tx`) est déjà auto-authentifiante (voir
//! `Tx::validate`) : un `PutChunk` par son empreinte BLAKE3, un
//! `PublishManifest` par la signature ML-DSA déjà portée par le
//! `Manifest`, un `Revoke` par sa propre signature. Elles sont donc
//! appliquées directement dès réception/validation, sans regroupement en
//! blocs ni preuve de travail.
//!
//! Anti-spam : limite de débit par identité (voir `RATE_LIMIT_PER_WINDOW`),
//! dérivée de l'horodatage d'acceptation (mtime) des fichiers persistés —
//! pas seulement de l'état mémoire d'un processus, pour qu'un CLI ponctuel
//! et un daemon sur le même `--home` partagent la même vérité sans verrou
//! inter-processus (l'adressage par contenu des transactions élimine déjà
//! tout risque de collision d'écriture entre processus).

use nv_core::identity::{Identity, PublicIdentity};
use nv_core::Manifest;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Fenêtre glissante et plafond du rate-limit anti-spam par identité.
pub const RATE_WINDOW_SECS: u64 = 60;
pub const RATE_LIMIT_PER_WINDOW: usize = 30;
/// Au-delà de cet âge, une révocation en attente de son manifeste est
/// purgée (évite une croissance illimitée si le manifeste n'arrive jamais).
pub const PENDING_REVOKE_MAX_AGE_SECS: u64 = 30 * 24 * 3600;
/// Au-delà de cet âge sans qu'aucun manifeste connu ne le référence, un
/// chunk est considéré orphelin et purgé (voir `purge_orphan_chunks`).
/// Assez long pour couvrir un `add` légitime interrompu entre l'envoi des
/// chunks et celui du manifeste (upload lent, crash du client) ; assez
/// court pour borner la croissance du disque face à un émetteur qui n'en
/// soumet jamais (une seule identité, sous le rate-limit, pouvait sinon
/// remplir le disque de tout nœud indéfiniment).
pub const ORPHAN_CHUNK_MAX_AGE_SECS: u64 = 24 * 3600;
/// Intervalle minimal entre deux passes de purge des chunks orphelins,
/// pour ne pas rescanner tout le disque à chaque `refresh()` (appelé
/// toutes les 5-10 s par le daemon).
pub const ORPHAN_PURGE_INTERVAL_SECS: u64 = 3600;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("erreur E/S : {0}")]
    Io(#[from] std::io::Error),
    #[error("format : {0}")]
    Format(String),
    #[error("transaction invalide : {0}")]
    Invalid(String),
    #[error("limite de débit dépassée pour cette identité")]
    RateLimited,
    #[error(transparent)]
    Core(#[from] nv_core::Error),
}

impl From<serde_json::Error> for LedgerError {
    fn from(e: serde_json::Error) -> Self {
        LedgerError::Format(e.to_string())
    }
}

/// Transaction : chunk chiffré, manifeste publié, ou révocation.
#[derive(Clone, Serialize, Deserialize)]
pub enum Tx {
    /// Chunk chiffré, contenu en base64. Son empreinte BLAKE3 doit
    /// correspondre à `hash`.
    PutChunk { hash: String, data_b64: String },
    /// Manifeste .nvault signé par son propriétaire.
    PublishManifest { manifest: Manifest },
    /// Révocation d'un fichier par son propriétaire : les nœuds purgent
    /// chunks et manifeste. `signature` = ML-DSA du propriétaire sur
    /// "revoke:" + file_id.
    Revoke {
        file_id: String,
        owner: PublicIdentity,
        signature: String,
    },
}

impl Tx {
    pub fn validate(&self) -> Result<(), LedgerError> {
        match self {
            Tx::PutChunk { hash, data_b64 } => {
                use base64::{engine::general_purpose::STANDARD as B64, Engine};
                let data = B64
                    .decode(data_b64)
                    .map_err(|e| LedgerError::Format(e.to_string()))?;
                if blake3::hash(&data).to_hex().to_string() != *hash {
                    return Err(LedgerError::Invalid(format!(
                        "empreinte de chunk incorrecte : {hash}"
                    )));
                }
                Ok(())
            }
            Tx::PublishManifest { manifest } => Ok(manifest.verify()?),
            Tx::Revoke { file_id, owner, signature } => {
                let msg = format!("revoke:{file_id}");
                Ok(owner.verify(msg.as_bytes(), signature)?)
            }
        }
    }
}

/// Construit une transaction de révocation signée.
pub fn make_revoke(file_id: &str, identity: &Identity) -> Result<Tx, LedgerError> {
    let signature = identity.sign(format!("revoke:{file_id}").as_bytes())?;
    Ok(Tx::Revoke {
        file_id: file_id.to_string(),
        owner: identity.public.clone(),
        signature,
    })
}

/// Enveloppe signée par l'émetteur : unité de soumission, de gossip et de
/// persistance pour toute transaction. C'est elle (et non la transaction
/// seule) qui porte l'attribution d'identité nécessaire au rate-limit —
/// en particulier pour `PutChunk`, qui n'a autrement aucun propriétaire.
#[derive(Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub tx: Tx,
    pub sender: PublicIdentity,
    pub signature: String,
}

impl Envelope {
    /// Signe `tx` au nom de `identity`, qui devient l'émetteur attribué.
    pub fn new(tx: Tx, identity: &Identity) -> Result<Self, LedgerError> {
        let bytes = serde_json::to_vec(&tx)?;
        let signature = identity.sign(&bytes)?;
        Ok(Envelope { tx, sender: identity.public.clone(), signature })
    }

    fn verify(&self) -> Result<(), LedgerError> {
        let bytes = serde_json::to_vec(&self.tx)?;
        self.sender.verify(&bytes, &self.signature)?;
        self.tx.validate()
    }

    /// Empreinte BLAKE3 (hex) de l'enveloppe entière : sert de clé de
    /// contenu pour la persistance, le déduplication et le gossip.
    pub fn key(&self) -> Result<String, LedgerError> {
        Ok(blake3::hash(&serde_json::to_vec(self)?).to_hex().to_string())
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn file_age_secs(path: &Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    Some(SystemTime::now().duration_since(modified).ok()?.as_secs())
}

/// Ledger persisté : un fichier JSON par enveloppe (nommé par son
/// empreinte) dans `dir/txs/`, chunks extraits dans `dir/chunks/`,
/// manifestes dans `dir/manifests/`.
pub struct Ledger {
    dir: PathBuf,
    chunk_index: HashMap<String, PathBuf>,
    manifests: Vec<Manifest>,
    /// Clés d'enveloppes déjà connues (déduplication / anti-inondation du
    /// gossip — un doublon n'est ni réappliqué ni rediffusé).
    seen: HashSet<String>,
    /// Révocations dont le manifeste ciblé n'était pas encore présent,
    /// appliquées dès que ce manifeste apparaît. Indépendant de l'ordre
    /// d'arrivée réseau ou de rejeu depuis le disque.
    pending_revokes: HashMap<String, Envelope>,
    /// Empreintes de chunks définitivement révoqués : un `PutChunk` tardif
    /// (rejeu dans le désordre, ou doublon réseau arrivé après coup) ne
    /// doit jamais ressusciter un chunk déjà purgé.
    revoked: HashSet<String>,
    /// Horodatages d'acceptation récents par identité (fenêtre glissante),
    /// reconstruits depuis le disque à l'ouverture : le rate-limit est
    /// ainsi partagé entre un CLI ponctuel et un daemon sur le même
    /// `--home`, sans coordination explicite.
    rate: HashMap<String, VecDeque<u64>>,
    /// Dernière passe de purge des chunks orphelins (secondes Unix).
    last_orphan_purge: u64,
}

impl Ledger {
    pub fn open(dir: &Path) -> Result<Self, LedgerError> {
        std::fs::create_dir_all(dir.join("txs"))?;
        std::fs::create_dir_all(dir.join("chunks"))?;
        std::fs::create_dir_all(dir.join("manifests"))?;
        let mut ledger = Ledger {
            dir: dir.to_path_buf(),
            chunk_index: HashMap::new(),
            manifests: Vec::new(),
            seen: HashSet::new(),
            pending_revokes: HashMap::new(),
            revoked: HashSet::new(),
            rate: HashMap::new(),
            last_orphan_purge: 0,
        };
        for entry in std::fs::read_dir(dir.join("txs"))? {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            let Ok(text) = std::fs::read_to_string(&path) else { continue };
            let Ok(envelope): Result<Envelope, _> = serde_json::from_str(&text) else { continue };
            let Some(age) = file_age_secs(&path) else { continue };
            ledger.replay(envelope, age);
        }
        // Purge les révocations orphelines devenues trop vieilles.
        ledger.pending_revokes.retain(|_, env| {
            let path = ledger.dir.join("txs").join(format!(
                "{}.json",
                env.key().unwrap_or_default()
            ));
            file_age_secs(&path).unwrap_or(0) < PENDING_REVOKE_MAX_AGE_SECS
        });
        ledger.purge_orphan_chunks();
        ledger.last_orphan_purge = now_secs();
        Ok(ledger)
    }

    /// Rejoue une enveloppe déjà persistée (chargement initial) : ni
    /// re-vérifiée, ni re-comptée pour le rate-limit (déjà acceptée par le
    /// passé), mais son horodatage alimente la fenêtre de rate-limit si
    /// encore dans la fenêtre glissante.
    fn replay(&mut self, envelope: Envelope, age_secs: u64) {
        let Ok(key) = envelope.key() else { return };
        if !self.seen.insert(key) {
            return;
        }
        if age_secs < RATE_WINDOW_SECS {
            let now = now_secs();
            self.rate
                .entry(envelope.sender.id())
                .or_default()
                .push_back(now.saturating_sub(age_secs));
        }
        self.apply(&envelope);
    }

    fn check_rate(&mut self, sender_id: &str) -> bool {
        let now = now_secs();
        let window = self.rate.entry(sender_id.to_string()).or_default();
        while window.front().is_some_and(|t| now.saturating_sub(*t) >= RATE_WINDOW_SECS) {
            window.pop_front();
        }
        if window.len() >= RATE_LIMIT_PER_WINDOW {
            return false;
        }
        window.push_back(now);
        true
    }

    /// Soumet une enveloppe (locale ou reçue par gossip) : vérifie sa
    /// signature et sa transaction, applique le rate-limit, persiste puis
    /// applique. `Ok(true)` = nouvelle transaction appliquée (à relayer),
    /// `Ok(false)` = déjà connue (aucune action), `Err` = rejetée
    /// (signature invalide, transaction invalide, ou rate-limit dépassé).
    pub fn submit(&mut self, envelope: Envelope) -> Result<bool, LedgerError> {
        let key = envelope.key()?;
        if self.seen.contains(&key) {
            return Ok(false);
        }
        envelope.verify()?;
        if !self.check_rate(&envelope.sender.id()) {
            return Err(LedgerError::RateLimited);
        }
        let path = self.dir.join("txs").join(format!("{key}.json"));
        std::fs::write(&path, serde_json::to_string(&envelope)?)?;
        self.seen.insert(key);
        self.apply(&envelope);
        Ok(true)
    }

    /// Applique une transaction déjà validée (interne : `submit`/`replay`).
    fn apply(&mut self, envelope: &Envelope) {
        match &envelope.tx {
            Tx::PutChunk { hash, data_b64 } => {
                // Un PutChunk pour un hash déjà révoqué ne doit jamais
                // ressusciter le chunk (rejeu dans le désordre, ou
                // doublon réseau arrivé après la révocation).
                if self.revoked.contains(hash) {
                    return;
                }
                use base64::{engine::general_purpose::STANDARD as B64, Engine};
                let cpath = self.dir.join("chunks").join(hash);
                if !cpath.exists() {
                    if let Ok(data) = B64.decode(data_b64) {
                        let _ = std::fs::write(&cpath, data);
                    }
                }
                self.chunk_index.insert(hash.clone(), cpath);
            }
            Tx::PublishManifest { manifest } => {
                let already = self
                    .manifests
                    .iter()
                    .any(|m| m.file_id == manifest.file_id && m.owner.id() == manifest.owner.id());
                if !already {
                    let mpath = self
                        .dir
                        .join("manifests")
                        .join(format!("{}.nvault", manifest.file_id));
                    if let Ok(text) = manifest.to_text() {
                        let _ = std::fs::write(&mpath, text);
                    }
                    self.manifests.push(manifest.clone());
                }
                // Une révocation arrivée avant ce manifeste est rejouée
                // maintenant, peu importe l'ordre d'origine.
                if let Some(pending) = self.pending_revokes.remove(&manifest.file_id) {
                    if let Tx::Revoke { owner, .. } = &pending.tx {
                        if owner.id() == manifest.owner.id() {
                            self.apply_revoke(&manifest.file_id, owner);
                        }
                    }
                }
            }
            Tx::Revoke { file_id, owner, .. } => {
                let target_present = self
                    .manifests
                    .iter()
                    .any(|m| m.file_id == *file_id && m.owner.id() == owner.id());
                if target_present {
                    self.apply_revoke(file_id, owner);
                } else {
                    // Bufferisée : appliquée dès que le manifeste apparaît.
                    self.pending_revokes.insert(file_id.clone(), envelope.clone());
                }
            }
        }
    }

    /// Retire manifeste + chunks non référencés ailleurs. N'appelle que
    /// si le manifeste ciblé est bien présent et vient de son propriétaire.
    fn apply_revoke(&mut self, file_id: &str, owner: &PublicIdentity) {
        let Some(pos) = self
            .manifests
            .iter()
            .position(|m| m.file_id == *file_id && m.owner.id() == owner.id())
        else {
            return;
        };
        let manifest = self.manifests.remove(pos);
        for h in &manifest.chunks {
            let used_elsewhere = self.manifests.iter().any(|m| m.chunks.contains(h));
            if !used_elsewhere {
                self.revoked.insert(h.clone());
                if let Some(p) = self.chunk_index.remove(h) {
                    let _ = std::fs::remove_file(p);
                }
            }
        }
        let _ = std::fs::remove_file(
            self.dir.join("manifests").join(format!("{file_id}.nvault")),
        );
    }

    /// Rattrape depuis le disque les enveloppes écrites par un autre
    /// processus sur le même `--home` (CLI ponctuel + daemon). Retourne
    /// `true` si au moins une nouvelle enveloppe a été rattrapée. Plus
    /// besoin de verrou inter-processus : les enveloppes sont adressées
    /// par contenu, donc deux processus n'écrivent jamais le même fichier.
    pub fn refresh(&mut self) -> Result<bool, LedgerError> {
        let mut updated = false;
        for entry in std::fs::read_dir(self.dir.join("txs"))? {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            let Ok(text) = std::fs::read_to_string(&path) else { continue };
            let Ok(envelope): Result<Envelope, _> = serde_json::from_str(&text) else { continue };
            let Ok(key) = envelope.key() else { continue };
            if self.seen.contains(&key) {
                continue;
            }
            let age = file_age_secs(&path).unwrap_or(0);
            self.replay(envelope, age);
            updated = true;
        }
        if now_secs().saturating_sub(self.last_orphan_purge) >= ORPHAN_PURGE_INTERVAL_SECS {
            self.purge_orphan_chunks();
            self.last_orphan_purge = now_secs();
        }
        Ok(updated)
    }

    /// Supprime les chunks stockés depuis plus de `ORPHAN_CHUNK_MAX_AGE_SECS`
    /// qu'aucun manifeste connu ne référence : un `PutChunk` valide dont le
    /// manifeste n'est jamais publié (panne du client entre les deux
    /// étapes, ou simplement un émetteur qui n'en soumet jamais) restait
    /// sinon sur disque indéfiniment — une seule identité, sous le
    /// rate-limit, pouvait ainsi remplir le disque de tout nœud sans
    /// limite dans le temps.
    fn purge_orphan_chunks(&mut self) {
        self.purge_orphan_chunks_capped(ORPHAN_CHUNK_MAX_AGE_SECS);
    }

    /// Cœur testable de `purge_orphan_chunks`, à seuil d'âge paramétrable
    /// (même principe que `decrypt_capped` dans nv-core : teste le
    /// mécanisme sans attendre 24h réelles).
    fn purge_orphan_chunks_capped(&mut self, max_age_secs: u64) {
        let referenced: HashSet<&str> = self
            .manifests
            .iter()
            .flat_map(|m| m.chunks.iter().map(String::as_str))
            .collect();
        let orphans: Vec<String> = self
            .chunk_index
            .iter()
            .filter(|(hash, path)| {
                !referenced.contains(hash.as_str())
                    && file_age_secs(path).unwrap_or(0) >= max_age_secs
            })
            .map(|(hash, _)| hash.clone())
            .collect();
        for hash in orphans {
            if let Some(path) = self.chunk_index.remove(&hash) {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    /// Toutes les enveloppes connues (pour resynchronisation réseau
    /// complète). Relit le disque à chaque appel : simple et suffisant à
    /// l'échelle actuelle du projet.
    pub fn all_envelopes(&self) -> Result<Vec<Envelope>, LedgerError> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(self.dir.join("txs"))? {
            let Ok(entry) = entry else { continue };
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                if let Ok(envelope) = serde_json::from_str(&text) {
                    out.push(envelope);
                }
            }
        }
        Ok(out)
    }

    /// Nombre de transactions connues — sert d'indicateur d'activité pour
    /// le CLI/la GUI (remplace la notion de "hauteur de chaîne").
    pub fn tx_count(&self) -> usize {
        self.seen.len()
    }

    pub fn manifests(&self) -> &[Manifest] {
        &self.manifests
    }

    pub fn get_chunk(&self, hash: &str) -> Option<Vec<u8>> {
        std::fs::read(self.chunk_index.get(hash)?).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nv_core::vault;

    fn chunk_tx(data: &[u8]) -> Tx {
        Tx::PutChunk {
            hash: blake3::hash(data).to_hex().to_string(),
            data_b64: {
                use base64::{engine::general_purpose::STANDARD as B64, Engine};
                B64.encode(data)
            },
        }
    }

    fn file_envelopes(enc: &vault::EncryptedFile, id: &Identity) -> Vec<Envelope> {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let mut envs: Vec<Envelope> = enc
            .chunks
            .iter()
            .map(|(h, d)| {
                Envelope::new(Tx::PutChunk { hash: h.clone(), data_b64: B64.encode(d) }, id).unwrap()
            })
            .collect();
        envs.push(Envelope::new(Tx::PublishManifest { manifest: enc.manifest.clone() }, id).unwrap());
        envs
    }

    #[test]
    fn ledger_persiste_et_recharge() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        {
            let mut ledger = Ledger::open(dir.path()).unwrap();
            ledger.submit(Envelope::new(chunk_tx(b"abc"), &id).unwrap()).unwrap();
            ledger.submit(Envelope::new(chunk_tx(b"def"), &id).unwrap()).unwrap();
            assert_eq!(ledger.tx_count(), 2);
        }
        let ledger = Ledger::open(dir.path()).unwrap();
        assert_eq!(ledger.tx_count(), 2);
        let h = blake3::hash(b"abc").to_hex().to_string();
        assert_eq!(ledger.get_chunk(&h).unwrap(), b"abc");
    }

    #[test]
    fn signature_invalide_rejetee() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let mut ledger = Ledger::open(dir.path()).unwrap();
        let mut envelope = Envelope::new(chunk_tx(b"abc"), &id).unwrap();
        envelope.signature = "bidon".into();
        assert!(ledger.submit(envelope).is_err());
        assert_eq!(ledger.tx_count(), 0);
    }

    #[test]
    fn rate_limit_par_identite() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let mut ledger = Ledger::open(dir.path()).unwrap();
        for i in 0..RATE_LIMIT_PER_WINDOW {
            let env = Envelope::new(chunk_tx(format!("chunk-{i}").as_bytes()), &id).unwrap();
            ledger.submit(env).unwrap();
        }
        // Une de plus dans la même fenêtre : rejetée.
        let env = Envelope::new(chunk_tx(b"de-trop"), &id).unwrap();
        assert!(matches!(ledger.submit(env), Err(LedgerError::RateLimited)));

        // Une autre identité n'est pas affectée par la limite de la première.
        let autre = Identity::generate();
        let env = Envelope::new(chunk_tx(b"autre-identite"), &autre).unwrap();
        assert!(ledger.submit(env).unwrap());
    }

    #[test]
    fn rate_limit_partage_entre_deux_instances_meme_dossier() {
        // Reproduit le scénario CLI ponctuel + daemon sur le même --home :
        // le rate-limit doit être dérivé du disque, pas seulement de la
        // mémoire d'un process, sinon relancer le CLI le contournerait.
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        {
            let mut premiere_instance = Ledger::open(dir.path()).unwrap();
            for i in 0..RATE_LIMIT_PER_WINDOW {
                let env = Envelope::new(chunk_tx(format!("c{i}").as_bytes()), &id).unwrap();
                premiere_instance.submit(env).unwrap();
            }
        }
        // Nouvelle instance (comme un nouveau process CLI) sur le même dossier.
        let mut seconde_instance = Ledger::open(dir.path()).unwrap();
        let env = Envelope::new(chunk_tx(b"depasse-la-limite"), &id).unwrap();
        assert!(matches!(seconde_instance.submit(env), Err(LedgerError::RateLimited)));
    }

    #[test]
    fn fichier_complet_via_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let mut ledger = Ledger::open(dir.path()).unwrap();
        let data = vec![7u8; 2 * nv_core::CHUNK_SIZE + 99];
        let enc = vault::encrypt(&data, "gros.bin", &id).unwrap();
        for env in file_envelopes(&enc, &id) {
            ledger.submit(env).unwrap();
        }
        let m = &ledger.manifests()[0];
        let out = vault::decrypt(m, &id, |h| ledger.get_chunk(h)).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn revocation_purge_les_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let mut ledger = Ledger::open(dir.path()).unwrap();
        let enc = vault::encrypt(b"a purger", "x.txt", &id).unwrap();
        let hash0 = enc.manifest.chunks[0].clone();
        for env in file_envelopes(&enc, &id) {
            ledger.submit(env).unwrap();
        }
        assert!(ledger.get_chunk(&hash0).is_some());

        let revoke = make_revoke(&enc.manifest.file_id, &id).unwrap();
        ledger.submit(Envelope::new(revoke, &id).unwrap()).unwrap();
        assert!(ledger.manifests().is_empty());
        assert!(ledger.get_chunk(&hash0).is_none());
    }

    #[test]
    fn revocation_par_un_tiers_invalide() {
        let id = Identity::generate();
        let intrus = Identity::generate();
        let dir = tempfile::tempdir().unwrap();
        let mut ledger = Ledger::open(dir.path()).unwrap();
        let enc = vault::encrypt(b"protege", "y.txt", &id).unwrap();
        for env in file_envelopes(&enc, &id) {
            ledger.submit(env).unwrap();
        }

        // L'intrus signe une révocation valide en soi… mais pas du bon
        // propriétaire : le manifeste reste.
        let revoke = make_revoke(&enc.manifest.file_id, &intrus).unwrap();
        ledger.submit(Envelope::new(revoke, &intrus).unwrap()).unwrap();
        assert_eq!(ledger.manifests().len(), 1);
    }

    #[test]
    fn revocation_avant_son_manifeste_est_bufferisee() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let mut ledger = Ledger::open(dir.path()).unwrap();
        let enc = vault::encrypt(b"ordre inverse", "z.txt", &id).unwrap();
        let hash0 = enc.manifest.chunks[0].clone();

        // La révocation arrive AVANT les PutChunk/PublishManifest.
        let revoke = make_revoke(&enc.manifest.file_id, &id).unwrap();
        ledger.submit(Envelope::new(revoke, &id).unwrap()).unwrap();
        assert!(ledger.manifests().is_empty(), "rien à révoquer pour l'instant : bufferisée");

        for env in file_envelopes(&enc, &id) {
            ledger.submit(env).unwrap();
        }
        // Dès que le manifeste apparaît, la révocation bufferisée s'applique.
        assert!(ledger.manifests().is_empty(), "la révocation en attente doit s'appliquer immédiatement");
        assert!(ledger.get_chunk(&hash0).is_none());
    }

    #[test]
    fn rejeu_depuis_le_disque_dans_le_desordre() {
        // Simule un rejeu où les fichiers texte apparaissent dans un ordre
        // arbitraire (le disque ne garantit aucun ordre) : le résultat
        // final doit être identique à un ordre "logique".
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let enc;
        {
            let mut ledger = Ledger::open(dir.path()).unwrap();
            let e = vault::encrypt(b"rejeu", "w.txt", &id).unwrap();
            for env in file_envelopes(&e, &id) {
                ledger.submit(env).unwrap();
            }
            let revoke = make_revoke(&e.manifest.file_id, &id).unwrap();
            ledger.submit(Envelope::new(revoke, &id).unwrap()).unwrap();
            enc = e;
        }
        // Rouverture : quel que soit l'ordre de lecture du répertoire,
        // le fichier doit rester révoqué (pas ressuscité).
        let ledger = Ledger::open(dir.path()).unwrap();
        assert!(ledger.manifests().is_empty());
        assert!(ledger.get_chunk(&enc.manifest.chunks[0]).is_none());
    }

    #[test]
    fn chunk_orphelin_purge_apres_expiration() {
        // Un PutChunk dont le manifeste n'arrive jamais (panne du client,
        // ou émetteur qui n'en soumet jamais) ne doit pas rester sur
        // disque indéfiniment.
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let mut ledger = Ledger::open(dir.path()).unwrap();
        let hash = blake3::hash(b"orphelin").to_hex().to_string();
        ledger.submit(Envelope::new(chunk_tx(b"orphelin"), &id).unwrap()).unwrap();
        assert!(ledger.get_chunk(&hash).is_some());

        // max_age_secs=0 : force la purge sans attendre 24h réelles.
        ledger.purge_orphan_chunks_capped(0);
        assert!(ledger.get_chunk(&hash).is_none());
    }

    #[test]
    fn chunk_reference_par_un_manifeste_survit_a_la_purge() {
        // Même avec un seuil d'âge à zéro, un chunk qu'un manifeste
        // connu référence encore ne doit jamais être purgé.
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let mut ledger = Ledger::open(dir.path()).unwrap();
        let enc = vault::encrypt(b"toujours utile", "v.txt", &id).unwrap();
        for env in file_envelopes(&enc, &id) {
            ledger.submit(env).unwrap();
        }
        ledger.purge_orphan_chunks_capped(0);
        assert!(ledger.get_chunk(&enc.manifest.chunks[0]).is_some());
        assert_eq!(ledger.manifests().len(), 1);
    }
}
