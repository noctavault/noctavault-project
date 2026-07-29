use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("erreur E/S : {0}")]
    Io(#[from] std::io::Error),
    #[error("format invalide : {0}")]
    Format(String),
    #[error("erreur cryptographique : {0}")]
    Crypto(String),
    #[error("signature invalide")]
    BadSignature,
    #[error("chunk manquant : {0}")]
    MissingChunk(String),
    #[error("empreinte de chunk incorrecte : {0}")]
    ChunkMismatch(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Format(e.to_string())
    }
}
