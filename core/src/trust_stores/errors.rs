use colored::*;
use openssl::error::ErrorStack;
use std::{env::VarError, error::Error, fmt, io};

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
                write!(
                    f,
                    "{}: Trust Store PEM Encoding Failed: {}",
                    "Error".red(),
                    err
                )
            }
            Self::PEMFileCreationError(err) => {
                write!(
                    f,
                    "{}: Trust Store PEM File creation Failed: {}",
                    "Error".red(),
                    err
                )
            }
            Self::WriteToFileError(err) => {
                write!(
                    f,
                    "{}: Trust Store Writing to PEM file: {}",
                    "Error".red(),
                    err
                )
            }
        }
    }
}

impl Error for TrustStoreError {}

#[derive(Debug)]
pub enum FirefoxTrustStoreError {
    ENVVariableNotFound(VarError, String),
    IOError(io::Error),
}

impl fmt::Display for FirefoxTrustStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ENVVariableNotFound(err, variable) => {
                write!(
                    f,
                    "{}: getting Environment varibale {} : {}",
                    "Error".red(),
                    variable,
                    err
                )
            }
            Self::IOError(err) => {
                write!(
                    f,
                    "{}: reading the default firefox directoryL {}",
                    "Error".red(),
                    err
                )
            }
        }
    }
}

impl Error for FirefoxTrustStoreError {}
