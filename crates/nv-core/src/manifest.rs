//! Manifeste .nvault : le « fichier texte léger » qui référence un fichier
//! chiffré. Sans la clé privée ML-KEM du propriétaire, il est inutilisable.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::identity::{Identity, PublicIdentity};
use crate::Error;

const HEADER: &str = "-----BEGIN NOCTAVAULT-----";
const FOOTER: &str = "-----END NOCTAVAULT-----";

/// Destinataire d'un fichier : la clé du fichier lui est enveloppée via sa
/// clé publique ML-KEM. Seule sa clé privée permet de la déballer.
#[derive(Clone, Serialize, Deserialize)]
pub struct Recipient {
    /// Identifiant court de l'identité publique destinataire.
    pub id: String,
    /// Ciphertext ML-KEM-1024 (encapsulation), base64.
    pub kem_ct: String,
    /// Nonce AES-GCM de l'enveloppe, base64.
    pub wrap_nonce: String,
    /// Clé du fichier chiffrée par le secret encapsulé, base64.
    pub wrapped_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    /// Identifiant du fichier : BLAKE3 du contenu clair, hex.
    pub file_id: String,
    /// Nom de fichier d'origine.
    pub name: String,
    /// Taille du fichier clair, en octets.
    pub size: u64,
    /// Horodatage Unix (secondes) de création.
    pub created: u64,
    /// Compression appliquée avant chiffrement : "zstd" ou "none".
    #[serde(default = "compression_none")]
    pub compression: String,
    /// file_id de la version précédente de ce fichier, s'il y en a une.
    #[serde(default)]
    pub prev_version: Option<String>,
    /// Identité publique du propriétaire.
    pub owner: PublicIdentity,
    /// Destinataires (le propriétaire inclus) pouvant déchiffrer le fichier.
    pub recipients: Vec<Recipient>,
    /// Empreintes BLAKE3 (hex) de chaque chunk chiffré, dans l'ordre.
    pub chunks: Vec<String>,
    /// Signature ML-DSA-65 du propriétaire sur le manifeste, base64.
    #[serde(default)]
    pub signature: String,
}

fn compression_none() -> String {
    "none".into()
}

/// 64 caractères hex minuscules : forme exacte de `blake3::hash(..).to_hex()`.
fn is_blake3_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Manifest {
    /// Octets canoniques signés : le manifeste sérialisé sans la signature.
    fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut m = self.clone();
        m.signature = String::new();
        Ok(serde_json::to_vec(&m)?)
    }

    pub fn sign(&mut self, identity: &Identity) -> Result<(), Error> {
        let bytes = self.canonical_bytes()?;
        self.signature = identity.sign(&bytes)?;
        Ok(())
    }

    pub fn verify(&self) -> Result<(), Error> {
        self.check_ids()?;
        let bytes = self.canonical_bytes()?;
        self.owner.verify(&bytes, &self.signature)
    }

    /// `file_id`, `chunks` et `prev_version` finissent dans un chemin de
    /// fichier (`manifests/{file_id}.nvault`) ou une clé de recherche de
    /// chunk : un manifeste vient d'un pair quelconque du réseau public
    /// (auto-signé par son propre émetteur, donc la signature seule ne
    /// garantit rien sur leur contenu), donc on impose la forme d'une
    /// empreinte BLAKE3 hex avant tout usage, pour empêcher une traversée
    /// de chemin (`file_id` du style `../../etc/...`).
    fn check_ids(&self) -> Result<(), Error> {
        if !is_blake3_hex(&self.file_id) {
            return Err(Error::Format(format!("file_id invalide : {}", self.file_id)));
        }
        if let Some(prev) = &self.prev_version {
            if !is_blake3_hex(prev) {
                return Err(Error::Format(format!("prev_version invalide : {prev}")));
            }
        }
        for chunk in &self.chunks {
            if !is_blake3_hex(chunk) {
                return Err(Error::Format(format!("empreinte de chunk invalide : {chunk}")));
            }
        }
        Ok(())
    }

    /// Sérialise au format texte .nvault.
    pub fn to_text(&self) -> Result<String, Error> {
        let json = serde_json::to_string_pretty(self)?;
        Ok(format!("{HEADER}\n{json}\n{FOOTER}\n"))
    }

    /// Analyse un fichier texte .nvault et vérifie sa signature.
    pub fn from_text(text: &str) -> Result<Self, Error> {
        let start = text
            .find(HEADER)
            .ok_or_else(|| Error::Format("en-tête .nvault manquant".into()))?
            + HEADER.len();
        let end = text
            .find(FOOTER)
            .ok_or_else(|| Error::Format("pied .nvault manquant".into()))?;
        let manifest: Manifest = serde_json::from_str(text[start..end].trim())?;
        manifest.verify()?;
        Ok(manifest)
    }

    pub fn save(&self, path: &Path) -> Result<(), Error> {
        std::fs::write(path, self.to_text()?)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        Self::from_text(&std::fs::read_to_string(path)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifeste_de_base(identity: &Identity) -> Manifest {
        let mut m = Manifest {
            version: 1,
            file_id: blake3::hash(b"contenu").to_hex().to_string(),
            name: "f.txt".into(),
            size: 7,
            created: 0,
            compression: "none".into(),
            prev_version: None,
            owner: identity.public.clone(),
            recipients: vec![],
            chunks: vec![],
            signature: String::new(),
        };
        m.sign(identity).unwrap();
        m
    }

    #[test]
    fn file_id_valide_accepte() {
        let id = Identity::generate();
        assert!(manifeste_de_base(&id).verify().is_ok());
    }

    // Un manifeste est auto-signé par son propre émetteur : n'importe qui
    // sur le réseau public peut donc forger un `file_id` malveillant et le
    // signer lui-même. Sans validation de forme, ce `file_id` finit
    // directement dans un chemin de fichier
    // (`manifests/{file_id}.nvault`) côté `nv-chain` — traversée de
    // chemin possible chez tout pair qui reçoit ce manifeste par gossip.
    #[test]
    fn file_id_traversee_de_chemin_rejete() {
        let id = Identity::generate();
        let mut m = manifeste_de_base(&id);
        m.file_id = "../../../../tmp/evil".into();
        m.sign(&id).unwrap();
        assert!(m.verify().is_err());
    }

    #[test]
    fn file_id_trop_court_rejete() {
        let id = Identity::generate();
        let mut m = manifeste_de_base(&id);
        // Un `file_id` trop court ferait paniquer `&file_id[..16]` côté CLI.
        m.file_id = "abcd".into();
        m.sign(&id).unwrap();
        assert!(m.verify().is_err());
    }

    #[test]
    fn chunk_invalide_rejete() {
        let id = Identity::generate();
        let mut m = manifeste_de_base(&id);
        m.chunks = vec!["pas-une-empreinte".into()];
        m.sign(&id).unwrap();
        assert!(m.verify().is_err());
    }
}
