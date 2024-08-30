use super::{distinguished_name::DistinguishedName, errors::X509Result};
use crate::{utils::generate_cert_key_pair, x509::errors::X509Error};
use openssl::{
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{X509Name, X509Req, X509ReqBuilder},
};
use std::{
    fs::File,
    io::{self, Write},
};

#[derive(Debug)]
pub struct CAReq {
    rsa_priv: Rsa<Private>,
    pkey: PKey<Private>,
    distinguished_name: DistinguishedName,
}

impl CAReq {
    pub fn new(distinguished_name: DistinguishedName) -> X509Result<Self> {
        match generate_cert_key_pair() {
            Ok((rsa_priv, pkey)) => Ok(CAReq {
                rsa_priv,
                pkey,
                distinguished_name,
            }),
            Err(err) => Err(X509Error::InitCARequestCertKeyPairError(err)),
        }
    }

    pub fn generate_certificate_sign_request(ca_req: Self) -> X509Result<X509Req> {
        let distinguished_name: X509Name =
            DistinguishedName::distinguished_name_builder(ca_req.distinguished_name)?;
        let mut cert_req: X509ReqBuilder = X509Req::builder()
            .map_err(|err: ErrorStack| X509Error::X509CertificateBuilderInitializeError(err))?;
        cert_req
            .set_subject_name(&distinguished_name)
            .map_err(|err: ErrorStack| {
                X509Error::X509CertificateBuilerEntryError(err, "Subject Name".to_string())
            })?;
        cert_req
            .set_pubkey(&ca_req.pkey)
            .map_err(|err: ErrorStack| {
                X509Error::X509CertificateBuilerEntryError(err, "Public Key".to_string())
            })?;
        cert_req
            .sign(&ca_req.pkey, MessageDigest::sha256())
            .map_err(|err: ErrorStack| {
                X509Error::X509CertificateBuilerEntryError(err, "Sign".to_string())
            })?;
        Ok(cert_req.build())
    }

    pub fn save_certificate_to_file(certificate: &X509Req, file_name: &str) -> X509Result<()> {
        let certificate_pem: Vec<u8> = certificate
            .to_pem()
            .map_err(|err: ErrorStack| X509Error::X509CSRToPEMError(err))?;
        let mut file: File = File::create(file_name)
            .map_err(|err: io::Error| X509Error::X509PEMFileCreationError(err))?;
        file.write_all(&certificate_pem)
            .map_err(|err: io::Error| X509Error::X509WriteToFileError(err))?;
        Ok(())
    }
}
