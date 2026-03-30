use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZenvError {
    #[error("project not initialized — run `zenv init` first")]
    NotInitialized,

    #[error("config error: {0}")]
    Config(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("cache error: {0}")]
    Cache(String),

    #[error("provider error: {0}")]
    Provider(String),

    #[error("sync error: {0}")]
    Sync(String),

    #[error("secret not found: {0}")]
    SecretNotFound(String),

    #[error("keychain error: {0}")]
    Keychain(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("command failed: {0}")]
    Command(String),
}
