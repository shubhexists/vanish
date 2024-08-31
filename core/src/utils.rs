use crate::{
    errors::{CertKeyPairError, CertKeyResult, SerialNumberError, SerialNumberResult},
    x509::{self, ca_cert::CACert},
};
use openssl::{
    asn1::Asn1Integer,
    bn::BigNum,
    error::ErrorStack,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::X509,
};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

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

pub fn get_certificates_from_data_dir() -> Result<(X509, PKey<Private>), Box<dyn Error>> {
    if let Some(ref data_dir) = *x509::DATA_DIR {
        if !data_dir.exists() {
            fs::create_dir_all(data_dir)?;
        }
        let ca_certfile: PathBuf = data_dir.join("ca_cert.pem");
        let ca_keyfile: PathBuf = data_dir.join("ca_key.pem");
        let ca_cert_file_str: &str = ca_certfile
            .to_str()
            .ok_or("Failed to convert ca_certfile path to string")?;
        let ca_key_file_str: &str = ca_keyfile
            .to_str()
            .ok_or("Failed to convert ca_keyfile path to string")?;
        let (cert, pkey) = CACert::load_ca_cert(ca_cert_file_str, ca_key_file_str)?;
        Ok((cert, pkey))
    } else {
        eprintln!("Unable to get Data Directory");
        std::process::exit(1);
    }
}
