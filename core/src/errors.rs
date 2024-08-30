use core::fmt;
use openssl::error::ErrorStack;
use std::error::Error;

pub type CertKeyResult<T> = Result<T, CertKeyPairError>;
pub type SerialNumberResult<T> = Result<T, SerialNumberError>;

#[derive(Debug)]
pub enum CertKeyPairError {
    RSAGenerationError(ErrorStack),
    PKeyCreationError(ErrorStack),
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

#[derive(Debug)]
pub enum SerialNumberError {
    BigNumberInitializationError(ErrorStack),
    RandomBigNumberGenerationError(ErrorStack),
    ConvertBigNumberToASN1Error(ErrorStack),
}

impl fmt::Display for SerialNumberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BigNumberInitializationError(err) => {
                write!(f, "Error Initializing Big Number : {}", err)
            }
            Self::RandomBigNumberGenerationError(err) => {
                write!(f, "Error creating a Random Big Number : {}", err)
            }
            Self::ConvertBigNumberToASN1Error(err) => {
                write!(f, "Error Converting Big Number to ASN1Integer: {}", err)
            }
        }
    }
}

impl Error for SerialNumberError {}
