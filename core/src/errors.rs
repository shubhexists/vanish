use core::fmt;
use std::error::Error;

pub type CertKeyResult<T> = Result<T, CertKeyPairError>;

#[derive(Debug)]
pub enum CertKeyPairError {
    RSAGenerationError(openssl::error::ErrorStack),
    PKeyCreationError(openssl::error::ErrorStack),
}

impl fmt::Display for CertKeyPairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PKeyCreationError(err) => write!(f, "Error Creating Key File : {}", err),
            Self::RSAGenerationError(err) => {
                write!(f, "Error Generating Certificate File : {}", err)
            }
        }
    }
}

impl Error for CertKeyPairError {}
