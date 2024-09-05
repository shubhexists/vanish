use colored::*;
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
            Self::PKeyCreationError(err) => {
                write!(f, "{}: Creating Key File : {}", "Error".red(), err)
            }
            Self::RSAGenerationError(err) => {
                write!(
                    f,
                    "{}: Generating Certificate File : {}",
                    "Error".red(),
                    err
                )
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
                write!(f, "{}: Initializing Big Number : {}", "Error".red(), err)
            }
            Self::RandomBigNumberGenerationError(err) => {
                write!(
                    f,
                    "{}: creating a Random Big Number : {}",
                    "Error".red(),
                    err
                )
            }
            Self::ConvertBigNumberToASN1Error(err) => {
                write!(
                    f,
                    "{}: Converting Big Number to ASN1Integer: {}",
                    "Error".red(),
                    err
                )
            }
        }
    }
}

impl Error for SerialNumberError {}
