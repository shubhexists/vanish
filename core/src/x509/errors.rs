use crate::errors::{CertKeyPairError, SerialNumberError};
use core::fmt;
use openssl::error::ErrorStack;
use std::{error::Error, io};

pub type X509Result<T> = Result<T, X509Error>;

#[derive(Debug)]
pub enum X509Error {
    InitCARequestCertKeyPairError(CertKeyPairError),
    X509NameBuilderInitializeError(ErrorStack),
    X509NameBuilderEntryError(ErrorStack, String, String),
    X509CertificateBuilderInitializeError(ErrorStack),
    X509CertificateBuilerEntryError(ErrorStack, String),
    X509CSRToPEMError(ErrorStack),
    X509PEMFileCreationError(io::Error),
    X509WriteToFileError(io::Error),
    InitSerialNumberGenerationError(SerialNumberError),
    GenerateNotBeforeError(ErrorStack),
    GenerateNotAfterError(ErrorStack),
}

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InitCARequestCertKeyPairError(err) => {
                write!(
                    f,
                    "Failed to initialize Certificate Signing Request : {}",
                    err
                )
            }
            Self::X509NameBuilderInitializeError(err) => {
                write!(f, "Failed to initialize Name Builder: {}", err)
            }
            Self::X509NameBuilderEntryError(err, entry, value) => {
                write!(
                    f,
                    "Error adding entry {} in name builder with value {} : {}",
                    entry, value, err
                )
            }
            Self::X509CertificateBuilderInitializeError(err) => {
                write!(f, "Failed to initialize Certificate Builder: {}", err)
            }
            Self::X509CertificateBuilerEntryError(err, entry) => {
                write!(
                    f,
                    "Error adding entry {} in Certificate builder : {}",
                    entry, err
                )
            }
            Self::X509CSRToPEMError(err) => {
                write!(f, "Error Converting Certificate to PEM : {}", err)
            }
            Self::X509PEMFileCreationError(err) => {
                write!(f, "Error creating PEM file at specified location: {}", err)
            }
            Self::X509WriteToFileError(err) => {
                write!(f, "Error writing to specified PEM file: {}", err)
            }
            Self::InitSerialNumberGenerationError(err) => {
                write!(f, "Error Generating Random Serial Number -> {}", err)
            }
            Self::GenerateNotBeforeError(err) => {
                write!(f, "Error Generating Not Before Time: {}", err)
            }
            Self::GenerateNotAfterError(err) => {
                write!(f, "Error Generating Not After Time: {}", err)
            }
        }
    }
}

impl Error for X509Error {}
