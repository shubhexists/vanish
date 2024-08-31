use super::{distinguished_name::DistinguishedName, errors::X509Result, Certificate};
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

pub struct CAReq {
    _rsa_priv: Rsa<Private>,
    pkey: PKey<Private>,
    distinguished_name: DistinguishedName,
}

impl Certificate for CAReq {
    type Output = X509Req;
    fn new(distinguished_name: DistinguishedName) -> X509Result<Self> {
        match generate_cert_key_pair() {
            Ok((rsa_priv, pkey)) => Ok(CAReq {
                _rsa_priv: rsa_priv,
                pkey,
                distinguished_name,
            }),
            Err(err) => Err(X509Error::InitCARequestCertKeyPairError(err)),
        }
    }

    fn generate_certificate(self) -> X509Result<Self::Output> {
        let distinguished_name: X509Name =
            DistinguishedName::distinguished_name_builder(self.distinguished_name)?;
        let mut cert_req: X509ReqBuilder = X509Req::builder()
            .map_err(|err: ErrorStack| X509Error::X509CertificateBuilderInitializeError(err))?;
        cert_req
            .set_subject_name(&distinguished_name)
            .map_err(|err: ErrorStack| {
                X509Error::X509CertificateBuilerEntryError(err, "Subject Name".to_string())
            })?;
        cert_req.set_pubkey(&self.pkey).map_err(|err: ErrorStack| {
            X509Error::X509CertificateBuilerEntryError(err, "Public Key".to_string())
        })?;
        cert_req
            .sign(&self.pkey, MessageDigest::sha256())
            .map_err(|err: ErrorStack| {
                X509Error::X509CertificateBuilerEntryError(err, "Sign".to_string())
            })?;
        Ok(cert_req.build())
    }
}

impl CAReq {
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
