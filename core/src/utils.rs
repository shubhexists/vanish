use crate::errors::{CertKeyPairError, CertKeyResult, SerialNumberError, SerialNumberResult};
use openssl::{
    asn1::Asn1Integer,
    bn::BigNum,
    error::ErrorStack,
    pkey::{PKey, Private},
    rsa::Rsa,
};

pub fn generate_cert_key_pair() -> CertKeyResult<(Rsa<Private>, PKey<Private>)> {
    let rsa: Rsa<Private> =
        Rsa::generate(2048).map_err(|err: ErrorStack| CertKeyPairError::RSAGenerationError(err))?;
    let pkey: PKey<Private> = PKey::from_rsa(rsa.clone())
        .map_err(|err: ErrorStack| CertKeyPairError::PKeyCreationError(err))?;
    Ok((rsa, pkey))
}

pub fn generate_certificate_serial_number() -> SerialNumberResult<Asn1Integer> {
    let mut serial_number: BigNum =
        BigNum::new().map_err(|err: ErrorStack| SerialNumberError::BigNumberInitializationError(err))?;
    serial_number
        .rand(128, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .map_err(|err: ErrorStack| SerialNumberError::RandomBigNumberGenerationError(err))?;
    Ok(serial_number
        .to_asn1_integer()
        .map_err(|err: ErrorStack| SerialNumberError::ConvertBigNumberToASN1Error(err))?)
}