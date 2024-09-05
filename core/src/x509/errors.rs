use crate::errors::{CertKeyPairError, SerialNumberError};
use colored::*;
use core::fmt;
use openssl::error::ErrorStack;
use std::{error::Error, io};

pub type X509Result<T> = Result<T, X509Error>;

#[derive(Debug)]
pub enum X509Error {
    PKCS8EncodingError(ErrorStack),
    PEMEncodingError(ErrorStack),
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
    BasicConstraintsInitializeError(ErrorStack),
    ErrorGettingPublicKeyFromCSR(ErrorStack),
    KeyUsageBuildError(ErrorStack),
    ExtendedKeyUsageBuildError(ErrorStack),
    ErrorReadingCertFile(io::Error, String),
    ErrorConvertingFileToData(ErrorStack, String),
    SANCouldNotBuildError(ErrorStack),
    CertificateStackInitializationError(ErrorStack),
    CertificateStackPushError(ErrorStack),
}

impl fmt::Display for X509Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertificateStackPushError(err) => {
                write!(
                    f,
                    "{}: Failed to push item to stack: {}",
                    "Error".red(),
                    err
                )
            }
            Self::CertificateStackInitializationError(err) => {
                write!(
                    f,
                    "{}: Failed to initialize extension stack: {}",
                    "Error".red(),
                    err
                )
            }
            Self::InitCARequestCertKeyPairError(err) => {
                write!(
                    f,
                    "{}: Failed to initialize Certificate Signing Request : {}",
                    "Error".red(),
                    err
                )
            }
            Self::X509NameBuilderInitializeError(err) => {
                write!(
                    f,
                    "{}: Failed to initialize Name Builder: {}",
                    "Error".red(),
                    err
                )
            }
            Self::X509NameBuilderEntryError(err, entry, value) => {
                write!(
                    f,
                    "{}: Adding entry {} in name builder with value {} : {}",
                    "Error".red(),
                    entry,
                    value,
                    err
                )
            }
            Self::X509CertificateBuilderInitializeError(err) => {
                write!(
                    f,
                    "{}: Failed to initialize Certificate Builder: {}",
                    "Error".red(),
                    err
                )
            }
            Self::X509CertificateBuilerEntryError(err, entry) => {
                write!(
                    f,
                    "{}: adding entry {} in Certificate builder : {}",
                    "Error".red(),
                    entry,
                    err
                )
            }
            Self::X509CSRToPEMError(err) => {
                write!(
                    f,
                    "{}: Converting Certificate to PEM : {}",
                    "Error".red(),
                    err
                )
            }
            Self::X509PEMFileCreationError(err) => {
                write!(
                    f,
                    "{}: creating PEM file at specified location: {}",
                    "Error".red(),
                    err
                )
            }
            Self::X509WriteToFileError(err) => {
                write!(
                    f,
                    "{}: writing to specified PEM file: {}",
                    "Error".red(),
                    err
                )
            }
            Self::InitSerialNumberGenerationError(err) => {
                write!(
                    f,
                    "{}: Generating Random Serial Number -> {}",
                    "Error".red(),
                    err
                )
            }
            Self::GenerateNotBeforeError(err) => {
                write!(f, "{}: Generating Not Before Time: {}", "Error".red(), err)
            }
            Self::GenerateNotAfterError(err) => {
                write!(f, "{}: Generating Not After Time: {}", "Error".red(), err)
            }
            Self::BasicConstraintsInitializeError(err) => {
                write!(
                    f,
                    "{}: Initializing Basic Constrainsts for Certificate: {}",
                    "Error".red(),
                    err
                )
            }
            Self::ErrorGettingPublicKeyFromCSR(err) => {
                write!(f, "{}: getting Public Key From CSR: {}", "Error".red(), err)
            }
            Self::KeyUsageBuildError(err) => {
                write!(
                    f,
                    "{}: building Key Usage for Certificate: {}",
                    "Error".red(),
                    err
                )
            }
            Self::ExtendedKeyUsageBuildError(err) => {
                write!(
                    f,
                    "{}: building Extended Key Usage for Certificate: {}",
                    "Error".red(),
                    err
                )
            }
            Self::ErrorReadingCertFile(err, path) => {
                writeln!(
                    f,
                    "{}: Reading Cert File at Path {} : {}",
                    "Error".red(),
                    path,
                    err
                )
            }
            Self::ErrorConvertingFileToData(err, path) => {
                writeln!(
                    f,
                    "{}: Converting file {} to desired data: {}",
                    "Error".red(),
                    path,
                    err
                )
            }
            Self::PKCS8EncodingError(err) => {
                writeln!(
                    f,
                    "{}: Failed to encode generated key to PKCS8 Format: {}",
                    "Error".red(),
                    err
                )
            }
            Self::PEMEncodingError(err) => {
                writeln!(
                    f,
                    "{}: Failed to encode generated certificate to PEM Format: {}",
                    "Error".red(),
                    err
                )
            }
            Self::SANCouldNotBuildError(err) => {
                write!(
                    f,
                    "{}: building Subject Alternative Name : {}",
                    "Error".red(),
                    err
                )
            }
        }
    }
}

impl Error for X509Error {}
