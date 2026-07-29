//! Identité : paire de clés ML-KEM-1024 (chiffrement) + ML-DSA-65 (signature).
//!
//! Fichier identité = JSON texte avec les clés en base64. La partie publique
//! seule peut être partagée ; la privée reste locale.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_traits::kem::{
    Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
};
use pqcrypto_traits::sign::{
    DetachedSignature as _, PublicKey as _, SecretKey as _,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::Error;

const ID_HEADER: &str = "-----BEGIN NOCTAVAULT ID-----";
const ID_FOOTER: &str = "-----END NOCTAVAULT ID-----";

/// Partie publique d'une identité (partageable).
#[derive(Clone, Serialize, Deserialize)]
pub struct PublicIdentity {
    /// Clé publique ML-KEM-1024, base64.
    pub kem_pk: String,
    /// Clé publique ML-DSA-65, base64.
    pub sig_pk: String,
}

impl PublicIdentity {
    /// Sérialise le « portefeuille public » au format texte .nvid.
    pub fn to_text(&self) -> Result<String, Error> {
        let json = serde_json::to_string_pretty(self)?;
        Ok(format!("{ID_HEADER}\n{json}\n{ID_FOOTER}\n"))
    }

    pub fn from_text(text: &str) -> Result<Self, Error> {
        let start = text
            .find(ID_HEADER)
            .ok_or_else(|| Error::Format("en-tête .nvid manquant".into()))?
            + ID_HEADER.len();
        let end = text
            .find(ID_FOOTER)
            .ok_or_else(|| Error::Format("pied .nvid manquant".into()))?;
        Ok(serde_json::from_str(text[start..end].trim())?)
    }

    pub fn save(&self, path: &Path) -> Result<(), Error> {
        std::fs::write(path, self.to_text()?)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        Self::from_text(&std::fs::read_to_string(path)?)
    }
    /// Identifiant court : BLAKE3 des deux clés publiques, hex tronqué.
    pub fn id(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(self.kem_pk.as_bytes());
        h.update(self.sig_pk.as_bytes());
        h.finalize().to_hex()[..16].to_string()
    }

    /// Vérifie une signature détachée ML-DSA sur `msg`.
    pub fn verify(&self, msg: &[u8], sig_b64: &str) -> Result<(), Error> {
        let pk_bytes = B64
            .decode(&self.sig_pk)
            .map_err(|e| Error::Format(e.to_string()))?;
        let pk = mldsa65::PublicKey::from_bytes(&pk_bytes)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let sig_bytes = B64
            .decode(sig_b64)
            .map_err(|e| Error::Format(e.to_string()))?;
        let sig = mldsa65::DetachedSignature::from_bytes(&sig_bytes)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        mldsa65::verify_detached_signature(&sig, msg, &pk)
            .map_err(|_| Error::BadSignature)
    }

    /// Encapsule une clé partagée de 32 octets vers cette identité.
    /// Retourne (clé partagée, ciphertext base64).
    pub fn encapsulate(&self) -> Result<([u8; 32], String), Error> {
        let pk_bytes = B64
            .decode(&self.kem_pk)
            .map_err(|e| Error::Format(e.to_string()))?;
        let pk = mlkem1024::PublicKey::from_bytes(&pk_bytes)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let (ss, ct) = mlkem1024::encapsulate(&pk);
        let mut key = [0u8; 32];
        key.copy_from_slice(ss.as_bytes());
        Ok((key, B64.encode(ct.as_bytes())))
    }
}

/// Identité complète (clés privées incluses). Ne jamais diffuser.
#[derive(Clone, Serialize, Deserialize)]
pub struct Identity {
    pub public: PublicIdentity,
    /// Clé secrète ML-KEM-1024, base64.
    kem_sk: String,
    /// Clé secrète ML-DSA-65, base64.
    sig_sk: String,
}

impl Identity {
    /// Génère une identité neuve.
    pub fn generate() -> Self {
        let (kem_pk, kem_sk) = mlkem1024::keypair();
        let (sig_pk, sig_sk) = mldsa65::keypair();
        Identity {
            public: PublicIdentity {
                kem_pk: B64.encode(kem_pk.as_bytes()),
                sig_pk: B64.encode(sig_pk.as_bytes()),
            },
            kem_sk: B64.encode(kem_sk.as_bytes()),
            sig_sk: B64.encode(sig_sk.as_bytes()),
        }
    }

    pub fn id(&self) -> String {
        self.public.id()
    }

    /// Signe `msg` (signature détachée ML-DSA-65, base64).
    pub fn sign(&self, msg: &[u8]) -> Result<String, Error> {
        let sk_bytes = B64
            .decode(&self.sig_sk)
            .map_err(|e| Error::Format(e.to_string()))?;
        let sk = mldsa65::SecretKey::from_bytes(&sk_bytes)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let sig = mldsa65::detached_sign(msg, &sk);
        Ok(B64.encode(sig.as_bytes()))
    }

    /// Décapsule la clé partagée depuis un ciphertext ML-KEM (base64).
    /// C'est la seule opération capable de retrouver la clé d'un fichier.
    pub fn decapsulate(&self, ct_b64: &str) -> Result<[u8; 32], Error> {
        let sk_bytes = B64
            .decode(&self.kem_sk)
            .map_err(|e| Error::Format(e.to_string()))?;
        let sk = mlkem1024::SecretKey::from_bytes(&sk_bytes)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let ct_bytes = B64
            .decode(ct_b64)
            .map_err(|e| Error::Format(e.to_string()))?;
        let ct = mlkem1024::Ciphertext::from_bytes(&ct_bytes)
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let ss = mlkem1024::decapsulate(&ct, &sk);
        let mut key = [0u8; 32];
        key.copy_from_slice(ss.as_bytes());
        Ok(key)
    }

    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, Error> {
        let json = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&json)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycle_encapsulation() {
        let id = Identity::generate();
        let (key, ct) = id.public.encapsulate().unwrap();
        let key2 = id.decapsulate(&ct).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn mauvaise_cle_ne_decapsule_pas() {
        let id = Identity::generate();
        let autre = Identity::generate();
        let (key, ct) = id.public.encapsulate().unwrap();
        // ML-KEM en échec implicite : une mauvaise clé rend une clé différente.
        let key2 = autre.decapsulate(&ct).unwrap();
        assert_ne!(key, key2);
    }

    #[test]
    fn signature_valide_et_invalide() {
        let id = Identity::generate();
        let sig = id.sign(b"bonjour").unwrap();
        id.public.verify(b"bonjour", &sig).unwrap();
        assert!(id.public.verify(b"autre", &sig).is_err());
    }

    #[test]
    fn sauvegarde_et_rechargement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.nvkey");
        let id = Identity::generate();
        id.save(&path).unwrap();
        let id2 = Identity::load(&path).unwrap();
        assert_eq!(id.id(), id2.id());
    }
}
