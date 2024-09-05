use crate::{
    errors::{CertKeyPairError, CertKeyResult, SerialNumberError, SerialNumberResult},
    x509::{self, ca_cert::CACert},
};
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use colored::*;
use openssl::{
    asn1::Asn1Integer,
    bn::BigNum,
    error::ErrorStack,
    pkey::{PKey, Private},
    rsa::Rsa,
    sha::Sha256,
    x509::X509,
};
use std::{
    error,
    fs::{self, File},
    io::{self, Read},
    path::Path,
    process::Output,
};
use std::{path::PathBuf, process::Command};

pub fn generate_cert_key_pair() -> CertKeyResult<(Rsa<Private>, PKey<Private>)> {
    let rsa: Rsa<Private> =
        Rsa::generate(2048).map_err(|err: ErrorStack| CertKeyPairError::RSAGenerationError(err))?;
    let pkey: PKey<Private> = PKey::from_rsa(rsa.clone())
        .map_err(|err: ErrorStack| CertKeyPairError::PKeyCreationError(err))?;
    Ok((rsa, pkey))
}

pub fn generate_certificate_serial_number() -> SerialNumberResult<Asn1Integer> {
    let mut serial_number: BigNum = BigNum::new()
        .map_err(|err: ErrorStack| SerialNumberError::BigNumberInitializationError(err))?;
    serial_number
        .rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .map_err(|err: ErrorStack| SerialNumberError::RandomBigNumberGenerationError(err))?;
    Ok(serial_number
        .to_asn1_integer()
        .map_err(|err: ErrorStack| SerialNumberError::ConvertBigNumberToASN1Error(err))?)
}

pub fn get_certificates_from_data_dir() -> Option<(X509, PKey<Private>)> {
    if let Some(ref data_dir) = *x509::DATA_DIR {
        if !data_dir.exists() {
            if let Err(err) = fs::create_dir_all(data_dir) {
                eprintln!(
                    "{}: Failed to create data directory: {}",
                    "Error".red(),
                    err
                );
                return None;
            }
        }
        let ca_certfile: PathBuf = data_dir.join("ca_cert.pem");
        let ca_keyfile: PathBuf = data_dir.join("ca_key.pem");

        let ca_cert_file_str: &str = match ca_certfile.to_str() {
            Some(s) => s,
            None => {
                eprintln!(
                    "{}: Failed to convert ca_certfile path to string",
                    "Error".red()
                );
                return None;
            }
        };

        let ca_key_file_str: &str = match ca_keyfile.to_str() {
            Some(s) => s,
            None => {
                eprintln!(
                    "{}: Failed to convert ca_keyfile path to string",
                    "Error".red()
                );
                return None;
            }
        };

        match CACert::load_ca_cert(ca_cert_file_str, ca_key_file_str) {
            Ok((cert, pkey)) => Some((cert, pkey)),
            Err(_err) => {
                eprintln!("{}: Generating new certificates ", "Warning".yellow());
                None
            }
        }
    } else {
        eprintln!("{}: Unable to get Data Directory", "Error".red());
        None
    }
}

pub fn save_generated_cert_key_files(
    cert: &X509,
    key: &PKey<Private>,
) -> Result<(), Box<dyn error::Error>> {
    println!();
    if let Some(ref data_dir) = *x509::DATA_DIR {
        if !data_dir.exists() {
            fs::create_dir_all(data_dir).map_err(|err| {
                eprintln!(
                    "{}: Failed to create data directory: {}",
                    "Error".red(),
                    err
                );
                err
            })?;
        }

        let ca_certfile: PathBuf = data_dir.join("ca_cert.pem");
        let ca_keyfile: PathBuf = data_dir.join("ca_key.pem");

        let ca_cert_file_str: &str = ca_certfile.to_str().ok_or_else(|| {
            let err: String = "Failed to convert ca_certfile path to string".to_string();
            eprintln!("{}: {}", "Error".red(), err);
            io::Error::new(io::ErrorKind::InvalidInput, err)
        })?;

        let ca_key_file_str: &str = ca_keyfile.to_str().ok_or_else(|| {
            let err: String = "Failed to convert ca_keyfile path to string".to_string();
            eprintln!("{}: {}", "Error".red(), err);
            io::Error::new(io::ErrorKind::InvalidInput, err)
        })?;

        match CACert::save_cert(cert, ca_cert_file_str) {
            Ok(()) => {
                println!(
                    "{}: CA Root Certificate saved at: {} 👍",
                    "Note".green(),
                    ca_cert_file_str
                );
            }
            Err(err) => {
                eprintln!("{}", err);
                std::process::exit(1);
            }
        };
        match CACert::save_key(key, ca_key_file_str) {
            Ok(()) => {
                println!(
                    "{}: CA Root Private Key saved at: {} 👍",
                    "Note".green(),
                    ca_cert_file_str
                );
            }
            Err(err) => {
                eprintln!("{}", err);
                std::process::exit(1);
            }
        };
        Ok(())
    } else {
        let err: String = "Unable to get Data Directory".to_string();
        eprintln!("{}: {}", "Error".red(), err);
        Err(Box::new(io::Error::new(io::ErrorKind::NotFound, err)))
    }
}

#[allow(dead_code)]
pub fn path_exists(path: &str) -> bool {
    Path::new(path).exists()
}

#[allow(dead_code)]
pub fn binary_exists(binary: &str) -> bool {
    Command::new(binary)
        .output()
        .map(|output: Output| output.status.success())
        .unwrap_or(false)
}

#[allow(dead_code)]
pub fn get_unique_hash(csr_path: &str) -> Result<String, io::Error> {
    let mut file: File = File::open(csr_path)?;
    let mut csr_contents: Vec<u8> = Vec::new();
    file.read_to_end(&mut csr_contents)?;
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(&csr_contents);
    let result: [u8; 32] = hasher.finish();
    let mut unique_name: String = URL_SAFE.encode(result);
    unique_name = unique_name.trim_end_matches('=').to_string();

    Ok(unique_name)
}
