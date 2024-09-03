use openssl::error::ErrorStack;
use std::{error::Error, fmt, io};

#[derive(Debug)]
pub enum TrustStoreError {
    PEMFileCreationError(io::Error),
    PEMEncodingError(ErrorStack),
    WriteToFileError(io::Error),
}

impl fmt::Display for TrustStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PEMEncodingError(err) => {
                write!(f, "Trust Store PEM Encoding Failed: {}", err)
            }
            Self::PEMFileCreationError(err) => {
                write!(f, "Trust Store PEM File creation Failed: {}", err)
            }
            Self::WriteToFileError(err) => {
                write!(f, "Trust Store Writing to PEM file: {}", err)
            }
        }
    }
}

impl Error for TrustStoreError {}