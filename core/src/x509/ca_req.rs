use super::{distinguished_name::DistinguishedName, errors::X509Result, Certificate};
use crate::{utils::generate_cert_key_pair, x509::errors::X509Error};
use openssl::{
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    stack::Stack,
    x509::{extension::SubjectAlternativeName, X509Extension, X509Name, X509Req, X509ReqBuilder},
};
use std::io::Read;
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
    type Output = (X509Req, PKey<Private>);
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
        let mut san: SubjectAlternativeName = SubjectAlternativeName::new();
        // For now as we test on localhost
        san.dns("localhost");
        let san: X509Extension = san
            .build(&cert_req.x509v3_context(None))
            .map_err(|err: ErrorStack| X509Error::SANCouldNotBuildError(err))?;
        let mut extension_stack: Stack<X509Extension> = Stack::<X509Extension>::new()
            .map_err(|err: ErrorStack| X509Error::CertificateStackInitializationError(err))?;
        extension_stack
            .push(san)
            .map_err(|err: ErrorStack| X509Error::CertificateStackPushError(err))?;
        cert_req
            .add_extensions(&extension_stack)
            .map_err(|err: ErrorStack| {
                X509Error::X509CertificateBuilerEntryError(
                    err,
                    "Subject Alternative Name".to_string(),
                )
            })?;

        cert_req
            .sign(&self.pkey, MessageDigest::sha256())
            .map_err(|err: ErrorStack| {
                X509Error::X509CertificateBuilerEntryError(err, "Sign".to_string())
            })?;
        Ok((cert_req.build(), self.pkey))
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

    pub fn read_csr_from_file(file_name: &str) -> X509Result<X509Req> {
        println!();
        let mut file: File = match File::open(file_name) {
            Ok(f) => f,
            Err(err) => {
                eprintln!("Reading Signing Request at {} ❌", file_name);
                return Err(X509Error::ErrorReadingCertFile(err, file_name.to_string()));
            }
        };

        let mut buffer: Vec<u8> = Vec::new();
        match file.read_to_end(&mut buffer) {
            Ok(_) => (),
            Err(err) => {
                eprintln!("Reading Signing Request at {} ❌", file_name);
                return Err(X509Error::ErrorReadingCertFile(err, file_name.to_string()));
            }
        };

        match X509Req::from_pem(&buffer) {
            Ok(csr) => {
                println!("Reading Signing Request at {} ✅", file_name);
                Ok(csr)
            }
            Err(err) => {
                eprintln!("Reading Signing Request at {} ❌", file_name);
                Err(X509Error::ErrorConvertingFileToData(
                    err,
                    file_name.to_string(),
                ))
            }
        }
    }

    pub fn save_key(key: &PKey<Private>, path: &str) -> X509Result<()> {
        let mut file: File = File::create(path)
            .map_err(|err: io::Error| X509Error::X509PEMFileCreationError(err))?;
        file.write_all(
            &key.private_key_to_pem_pkcs8()
                .map_err(|err: ErrorStack| X509Error::PKCS8EncodingError(err))?,
        )
        .map_err(|err: io::Error| X509Error::X509WriteToFileError(err))?;
        Ok(())
    }
}
