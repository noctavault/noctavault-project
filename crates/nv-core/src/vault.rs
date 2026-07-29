//! Chiffrement / déchiffrement de fichiers.
//!
//! Schéma hybride KEM-DEM multi-destinataires :
//! - clé de fichier aléatoire (32 octets) ;
//! - pour chaque destinataire : ML-KEM-1024 encapsule un secret vers sa clé
//!   publique, et ce secret sert de clé AES-GCM pour envelopper la clé de
//!   fichier ;
//! - le contenu est compressé (zstd) puis chiffré par chunks AES-256-GCM.
//!
//! Chunk chiffré = nonce (12 octets) || AES-256-GCM(chunk compressé).
//! AAD = DOMAIN || file_id || index du chunk (u32 BE).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

use crate::identity::{Identity, PublicIdentity};
use crate::manifest::{Manifest, Recipient};
use crate::{Error, CHUNK_SIZE, DOMAIN, MAX_DECOMPRESSED_SIZE};

/// Résultat du chiffrement d'un fichier : le manifeste signé et les chunks
/// chiffrés (à diffuser sur le réseau), indexés par leur empreinte BLAKE3.
pub struct EncryptedFile {
    pub manifest: Manifest,
    /// (empreinte hex, contenu chiffré) dans l'ordre des chunks.
    pub chunks: Vec<(String, Vec<u8>)>,
}

fn aad(file_id: &str, index: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DOMAIN.len() + file_id.len() + 4);
    aad.extend_from_slice(DOMAIN);
    aad.extend_from_slice(file_id.as_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad
}

/// Enveloppe `file_key` vers une identité publique.
fn wrap_key(to: &PublicIdentity, file_key: &[u8; 32]) -> Result<Recipient, Error> {
    let (mut ss, kem_ct) = to.encapsulate()?;
    let cipher =
        Aes256Gcm::new_from_slice(&ss).map_err(|e| Error::Crypto(e.to_string()))?;
    ss.zeroize();
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let wrapped = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), file_key.as_slice())
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(Recipient {
        id: to.id(),
        kem_ct,
        wrap_nonce: B64.encode(nonce_bytes),
        wrapped_key: B64.encode(wrapped),
    })
}

/// Déballe la clé de fichier depuis l'entrée destinataire correspondant à
/// `identity`. Échoue si l'identité n'est pas destinataire.
fn unwrap_key(manifest: &Manifest, identity: &Identity) -> Result<[u8; 32], Error> {
    let my_id = identity.id();
    // L'entrée à notre id d'abord, puis les autres par prudence.
    let ordered = manifest
        .recipients
        .iter()
        .filter(|r| r.id == my_id)
        .chain(manifest.recipients.iter().filter(|r| r.id != my_id));
    for r in ordered {
        let Ok(mut ss) = identity.decapsulate(&r.kem_ct) else { continue };
        let Ok(cipher) = Aes256Gcm::new_from_slice(&ss) else { continue };
        ss.zeroize();
        let (Ok(nonce), Ok(wrapped)) = (B64.decode(&r.wrap_nonce), B64.decode(&r.wrapped_key))
        else {
            continue;
        };
        if let Ok(key) = cipher.decrypt(Nonce::from_slice(&nonce), wrapped.as_slice()) {
            if key.len() == 32 {
                let mut out = [0u8; 32];
                out.copy_from_slice(&key);
                return Ok(out);
            }
        }
    }
    Err(Error::Crypto(
        "cette clé privée n'est pas destinataire de ce fichier".into(),
    ))
}

/// Chiffre `data` pour le propriétaire `identity` et les destinataires
/// supplémentaires `to`, et produit manifeste + chunks.
pub fn encrypt_for(
    data: &[u8],
    name: &str,
    identity: &Identity,
    to: &[PublicIdentity],
    prev_version: Option<String>,
) -> Result<EncryptedFile, Error> {
    let file_id = blake3::hash(data).to_hex().to_string();

    let mut file_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut file_key);
    let mut recipients = vec![wrap_key(&identity.public, &file_key)?];
    for pk in to {
        if pk.id() != identity.id() {
            recipients.push(wrap_key(pk, &file_key)?);
        }
    }

    let cipher = Aes256Gcm::new_from_slice(&file_key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    file_key.zeroize();

    // Compression avant chiffrement (le chiffré ne se compresse pas).
    let compressed =
        zstd::encode_all(data, 3).map_err(|e| Error::Crypto(e.to_string()))?;

    let mut chunks = Vec::new();
    let mut hashes = Vec::new();
    let parts: Vec<&[u8]> = if compressed.is_empty() {
        vec![&[]]
    } else {
        compressed.chunks(CHUNK_SIZE).collect()
    };
    for (i, part) in parts.into_iter().enumerate() {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload { msg: part, aad: &aad(&file_id, i as u32) })
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let mut blob = nonce_bytes.to_vec();
        blob.extend_from_slice(&ct);
        let hash = blake3::hash(&blob).to_hex().to_string();
        hashes.push(hash.clone());
        chunks.push((hash, blob));
    }

    let mut manifest = Manifest {
        version: 2,
        file_id,
        name: name.to_string(),
        size: data.len() as u64,
        created: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        compression: "zstd".into(),
        prev_version,
        owner: identity.public.clone(),
        recipients,
        chunks: hashes,
        signature: String::new(),
    };
    manifest.sign(identity)?;
    Ok(EncryptedFile { manifest, chunks })
}

/// Chiffre `data` pour le seul propriétaire.
pub fn encrypt(data: &[u8], name: &str, identity: &Identity) -> Result<EncryptedFile, Error> {
    encrypt_for(data, name, identity, &[], None)
}

/// Déchiffre un fichier depuis son manifeste et un accès aux chunks par
/// empreinte. Échoue si `identity` n'est pas dans les destinataires.
pub fn decrypt(
    manifest: &Manifest,
    identity: &Identity,
    get_chunk: impl FnMut(&str) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, Error> {
    decrypt_capped(manifest, identity, get_chunk, MAX_DECOMPRESSED_SIZE)
}

/// Cœur de `decrypt`, avec la limite de décompression en paramètre pour
/// pouvoir la tester à petite échelle (voir les tests).
fn decrypt_capped(
    manifest: &Manifest,
    identity: &Identity,
    mut get_chunk: impl FnMut(&str) -> Option<Vec<u8>>,
    max_decompressed: u64,
) -> Result<Vec<u8>, Error> {
    manifest.verify()?;
    let mut file_key = unwrap_key(manifest, identity)?;
    let cipher = Aes256Gcm::new_from_slice(&file_key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    file_key.zeroize();

    let mut compressed = Vec::new();
    for (i, hash) in manifest.chunks.iter().enumerate() {
        let blob = get_chunk(hash).ok_or_else(|| Error::MissingChunk(hash.clone()))?;
        if blake3::hash(&blob).to_hex().to_string() != *hash {
            return Err(Error::ChunkMismatch(hash.clone()));
        }
        if blob.len() < 12 {
            return Err(Error::Format("chunk trop court".into()));
        }
        let (nonce_bytes, ct) = blob.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let part = cipher
            .decrypt(nonce, Payload { msg: ct, aad: &aad(&manifest.file_id, i as u32) })
            .map_err(|_| Error::Crypto("déchiffrement du chunk refusé (mauvaise clé ?)".into()))?;
        compressed.extend_from_slice(&part);
    }

    let data = match manifest.compression.as_str() {
        "zstd" => {
            let decoder = zstd::stream::Decoder::new(compressed.as_slice())
                .map_err(|e| Error::Crypto(e.to_string()))?;
            let mut out = Vec::new();
            decoder
                .take(max_decompressed + 1)
                .read_to_end(&mut out)
                .map_err(|e| Error::Crypto(e.to_string()))?;
            if out.len() as u64 > max_decompressed {
                return Err(Error::Format("fichier décompressé trop volumineux".into()));
            }
            out
        }
        "none" => compressed,
        other => return Err(Error::Format(format!("compression inconnue : {other}"))),
    };
    if blake3::hash(&data).to_hex().to_string() != manifest.file_id {
        return Err(Error::Crypto("empreinte du fichier reconstruit incorrecte".into()));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn store(enc: &EncryptedFile) -> HashMap<String, Vec<u8>> {
        enc.chunks.iter().cloned().collect()
    }

    #[test]
    fn cycle_complet() {
        let id = Identity::generate();
        // Données incompressibles pour exercer plusieurs chunks.
        let mut data = vec![0u8; 3 * CHUNK_SIZE + 12345];
        rand::thread_rng().fill_bytes(&mut data);
        let enc = encrypt(&data, "test.bin", &id).unwrap();
        assert!(enc.manifest.chunks.len() >= 4);
        let map = store(&enc);
        let out = decrypt(&enc.manifest, &id, |h| map.get(h).cloned()).unwrap();
        assert_eq!(out, data);
    }

    // Le contenu chiffré vient potentiellement d'un émetteur quelconque du
    // réseau public : un chunk compressé minuscule peut, par construction
    // du format zstd, décompresser en une taille bien plus grande
    // (« bombe » de décompression). `max_decompressed` est ici réduit
    // pour tester le mécanisme sans manipuler des gigaoctets réels.
    #[test]
    fn decompression_bombe_rejetee_au_dela_du_plafond() {
        let id = Identity::generate();
        let data = vec![0u8; 10_000]; // très compressible, chunk minuscule
        let enc = encrypt(&data, "bombe.bin", &id).unwrap();
        let map = store(&enc);
        let err = decrypt_capped(&enc.manifest, &id, |h| map.get(h).cloned(), 100).unwrap_err();
        assert!(matches!(err, Error::Format(_)));
    }

    #[test]
    fn decompression_sous_le_plafond_acceptee() {
        let id = Identity::generate();
        let data = vec![0u8; 10_000];
        let enc = encrypt(&data, "ok.bin", &id).unwrap();
        let map = store(&enc);
        let out = decrypt_capped(&enc.manifest, &id, |h| map.get(h).cloned(), 20_000).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn compression_reduit_la_chaine() {
        let id = Identity::generate();
        let data = vec![42u8; 3 * CHUNK_SIZE]; // très compressible
        let enc = encrypt(&data, "zeros.bin", &id).unwrap();
        let total: usize = enc.chunks.iter().map(|(_, d)| d.len()).sum();
        assert!(total < CHUNK_SIZE / 2, "compressé = {total} octets");
        let map = store(&enc);
        let out = decrypt(&enc.manifest, &id, |h| map.get(h).cloned()).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn fichier_vide_et_petit() {
        let id = Identity::generate();
        for data in [vec![], b"bonjour".to_vec()] {
            let enc = encrypt(&data, "petit.txt", &id).unwrap();
            let map = store(&enc);
            let out = decrypt(&enc.manifest, &id, |h| map.get(h).cloned()).unwrap();
            assert_eq!(out, data);
        }
    }

    #[test]
    fn partage_multi_destinataires() {
        let auteur = Identity::generate();
        let amie = Identity::generate();
        let intrus = Identity::generate();
        let enc =
            encrypt_for(
                b"secret partage",
                "s.txt",
                &auteur,
                std::slice::from_ref(&amie.public),
                None,
            )
            .unwrap();
        assert_eq!(enc.manifest.recipients.len(), 2);
        let map = store(&enc);
        // L'auteur et l'amie déchiffrent, l'intrus non.
        for who in [&auteur, &amie] {
            let out = decrypt(&enc.manifest, who, |h| map.get(h).cloned()).unwrap();
            assert_eq!(out, b"secret partage");
        }
        assert!(decrypt(&enc.manifest, &intrus, |h| map.get(h).cloned()).is_err());
    }

    #[test]
    fn manifeste_altere_rejete() {
        let id = Identity::generate();
        let enc = encrypt(b"secret", "s.txt", &id).unwrap();
        let mut m = enc.manifest.clone();
        m.name = "pirate.txt".into();
        assert!(matches!(m.verify(), Err(Error::BadSignature)));
    }

    #[test]
    fn chunk_altere_rejete() {
        let id = Identity::generate();
        let enc = encrypt(b"secret", "s.txt", &id).unwrap();
        let mut map = store(&enc);
        let h = enc.manifest.chunks[0].clone();
        map.get_mut(&h).unwrap()[20] ^= 0xff;
        assert!(decrypt(&enc.manifest, &id, |x| map.get(x).cloned()).is_err());
    }

    #[test]
    fn versionnage() {
        let id = Identity::generate();
        let v1 = encrypt(b"version 1", "doc.txt", &id).unwrap();
        let v2 = encrypt_for(
            b"version 2",
            "doc.txt",
            &id,
            &[],
            Some(v1.manifest.file_id.clone()),
        )
        .unwrap();
        assert_eq!(v2.manifest.prev_version.as_deref(), Some(v1.manifest.file_id.as_str()));
    }

    #[test]
    fn format_texte_nvault() {
        let id = Identity::generate();
        let enc = encrypt(b"contenu", "doc.txt", &id).unwrap();
        let text = enc.manifest.to_text().unwrap();
        assert!(text.starts_with("-----BEGIN NOCTAVAULT-----"));
        assert!(text.len() < 24 * 1024);
        let m = Manifest::from_text(&text).unwrap();
        assert_eq!(m.file_id, enc.manifest.file_id);
    }

    #[test]
    fn portefeuille_public_nvid() {
        let id = Identity::generate();
        let text = id.public.to_text().unwrap();
        let pk = crate::identity::PublicIdentity::from_text(&text).unwrap();
        assert_eq!(pk.id(), id.id());
    }
}
