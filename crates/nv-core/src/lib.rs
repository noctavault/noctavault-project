//! Noctavault core : cryptographie post-quantique, manifestes .nvault, chunking.
//!
//! Schéma :
//! - Identité = ML-KEM-1024 (encapsulation de clé) + ML-DSA-65 (signature).
//! - Un fichier est découpé en chunks de 1 MiB, chiffrés en AES-256-GCM avec
//!   une clé de fichier aléatoire.
//! - La clé de fichier est encapsulée vers la clé publique ML-KEM du
//!   propriétaire : seule la clé privée correspondante peut la récupérer.
//! - Le manifeste .nvault (texte, quelques Ko) contient métadonnées,
//!   encapsulation, empreintes BLAKE3 des chunks chiffrés, signature ML-DSA.

pub mod error;
pub mod identity;
pub mod manifest;
pub mod vault;

pub use error::Error;
pub use identity::Identity;
pub use manifest::Manifest;

/// Taille d'un chunk en clair (1 MiB).
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Contexte de domaine pour les données authentifiées (AAD).
pub const DOMAIN: &[u8] = b"noctavault.v1";

/// Plafond de taille pour un fichier décompressé (4 GiB). Protection contre
/// une bombe de décompression zstd : un chunk compressé, minuscule et
/// parfaitement valide, peut par construction du format décompresser en
/// une taille bien plus grande — et le contenu chiffré vient d'un émetteur
/// quelconque du réseau public, jamais garanti bienveillant.
pub const MAX_DECOMPRESSED_SIZE: u64 = 4 * 1024 * 1024 * 1024;
