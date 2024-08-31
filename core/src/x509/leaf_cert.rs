use super::{
    distinguished_name::DistinguishedName,
    errors::{X509Error, X509Result},
    X509Version,
};
use crate::utils::{generate_cert_key_pair, generate_certificate_serial_number};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    error::ErrorStack,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    x509::{
        extension::{ExtendedKeyUsage, KeyUsage},
        X509Builder, X509Name, X509NameRef, X509Req, X509,
    },
};
use std::io::Write;
use std::{fs::File, io};

pub struct LeafCert {
    _rsa_priv: Rsa<Private>,
    _pkey: PKey<Private>,
    distinguished_name: DistinguishedName,
    version: X509Version,
    not_before: Asn1Time,
    not_after: Asn1Time,
    serial_number: Asn1Integer,
}

impl LeafCert {
    pub fn new(distinguished_name: DistinguishedName) -> X509Result<Self> {
        match generate_cert_key_pair() {
            Ok((rsa_priv, pkey)) => match generate_certificate_serial_number() {
                Ok(serial_number) => {
                    let not_before: Asn1Time = Asn1Time::days_from_now(0)
                        .map_err(|err: ErrorStack| X509Error::GenerateNotBeforeError(err))?;
                    let not_after: Asn1Time = Asn1Time::days_from_now(365 * 2)
                        .map_err(|err: ErrorStack| X509Error::GenerateNotAfterError(err))?;
                    Ok(LeafCert {
                        _rsa_priv: rsa_priv,
                        _pkey: pkey,
                        distinguished_name,
                        version: X509Version::V3,
                        not_before,
                        not_after,
                        serial_number,
                    })
                }
                Err(err) => Err(X509Error::InitSerialNumberGenerationError(err)),
            },
            Err(err) => Err(X509Error::InitCARequestCertKeyPairError(err)),
        }
    }

    pub fn generate_certificate(
        self,
        cert_file: &X509,
        key_file: &PKey<Private>,
        csr: Option<&X509Req>,
    ) -> X509Result<(X509, Option<PKey<Private>>)> {
        if let Some(csr) = csr {
            let pkey: PKey<Public> = csr
                .public_key()
                .map_err(|err: ErrorStack| X509Error::ErrorGettingPublicKeyFromCSR(err))?;
            let subject_name: &X509NameRef = csr.subject_name();
            let mut cert_builder: X509Builder = X509Builder::new()
                .map_err(|err: ErrorStack| X509Error::X509CertificateBuilderInitializeError(err))?;
            cert_builder
                .set_version(self.version as i32)
                .map_err(|err: ErrorStack| {
                    X509Error::X509CertificateBuilerEntryError(err, "Version".to_string())
                })?;
            cert_builder
                .set_subject_name(subject_name)
                .map_err(|err: ErrorStack| {
                    X509Error::X509CertificateBuilerEntryError(err, "Subject Name".to_string())
                })?;
            cert_builder
                .set_issuer_name(cert_file.subject_name())
                .map_err(|err: ErrorStack| {
                    X509Error::X509CertificateBuilerEntryError(err, "Issuer Name".to_string())
                })?;
            cert_builder.set_pubkey(&pkey).map_err(|err: ErrorStack| {
                X509Error::X509CertificateBuilerEntryError(err, "Public Key".to_string())
            })?;
            cert_builder
                .set_not_before(&self.not_before)
                .map_err(|err: ErrorStack| {
                    X509Error::X509CertificateBuilerEntryError(err, "Not Before".to_string())
                })?;
            cert_builder
                .set_not_after(&self.not_after)
                .map_err(|err: ErrorStack| {
                    X509Error::X509CertificateBuilerEntryError(err, "Not After".to_string())
                })?;
            cert_builder
                .set_serial_number(&self.serial_number)
                .map_err(|err: ErrorStack| {
                    X509Error::X509CertificateBuilerEntryError(err, "Serial Number".to_string())
                })?;
            cert_builder
                .append_extension(
                    KeyUsage::new()
                        .digital_signature()
                        .key_encipherment()
                        .build()
                        .map_err(|err: ErrorStack| X509Error::KeyUsageBuildError(err))?,
                )
                .map_err(|err: ErrorStack| {
                    X509Error::X509CertificateBuilerEntryError(err, "KeyUsage".to_string())
                })?;

            cert_builder
                .append_extension(
                    ExtendedKeyUsage::new()
                        .server_auth()
                        .client_auth()
                        .build()
                        .map_err(|err: ErrorStack| X509Error::ExtendedKeyUsageBuildError(err))?,
                )
                .map_err(|err: ErrorStack| {
                    X509Error::X509CertificateBuilerEntryError(err, "ExtendedKeyUsage".to_string())
                })?;

            cert_builder
                .sign(key_file, MessageDigest::sha256())
                .map_err(|err: ErrorStack| {
                    X509Error::X509CertificateBuilerEntryError(err, "Sign".to_string())
                })?;

            return Ok((cert_builder.build(), None));
        } else {
            match generate_cert_key_pair() {
                Ok((_rsa_priv, pkey)) => {
                    let distinguished_name: X509Name =
                        DistinguishedName::distinguished_name_builder(self.distinguished_name)?;
                    let mut cert_builder: X509Builder =
                        X509Builder::new().map_err(|err: ErrorStack| {
                            X509Error::X509CertificateBuilderInitializeError(err)
                        })?;
                    cert_builder
                        .set_version(self.version as i32)
                        .map_err(|err: ErrorStack| {
                            X509Error::X509CertificateBuilerEntryError(err, "Version".to_string())
                        })?;
                    cert_builder.set_subject_name(&distinguished_name).map_err(
                        |err: ErrorStack| {
                            X509Error::X509CertificateBuilerEntryError(
                                err,
                                "Subject Name".to_string(),
                            )
                        },
                    )?;
                    cert_builder
                        .set_issuer_name(cert_file.subject_name())
                        .map_err(|err: ErrorStack| {
                            X509Error::X509CertificateBuilerEntryError(
                                err,
                                "Issuer Name".to_string(),
                            )
                        })?;
                    cert_builder.set_pubkey(&pkey).map_err(|err: ErrorStack| {
                        X509Error::X509CertificateBuilerEntryError(err, "Public Key".to_string())
                    })?;
                    cert_builder
                        .set_not_before(&self.not_before)
                        .map_err(|err: ErrorStack| {
                            X509Error::X509CertificateBuilerEntryError(
                                err,
                                "Not Before".to_string(),
                            )
                        })?;
                    cert_builder
                        .set_not_after(&self.not_after)
                        .map_err(|err: ErrorStack| {
                            X509Error::X509CertificateBuilerEntryError(err, "Not After".to_string())
                        })?;
                    cert_builder
                        .set_serial_number(&self.serial_number)
                        .map_err(|err: ErrorStack| {
                            X509Error::X509CertificateBuilerEntryError(
                                err,
                                "Serial Number".to_string(),
                            )
                        })?;
                    cert_builder
                        .append_extension(
                            KeyUsage::new()
                                .digital_signature()
                                .key_encipherment()
                                .build()
                                .map_err(|err: ErrorStack| X509Error::KeyUsageBuildError(err))?,
                        )
                        .map_err(|err: ErrorStack| {
                            X509Error::X509CertificateBuilerEntryError(err, "KeyUsage".to_string())
                        })?;

                    cert_builder
                        .append_extension(
                            ExtendedKeyUsage::new()
                                .server_auth()
                                .client_auth()
                                .build()
                                .map_err(|err: ErrorStack| {
                                    X509Error::ExtendedKeyUsageBuildError(err)
                                })?,
                        )
                        .map_err(|err: ErrorStack| {
                            X509Error::X509CertificateBuilerEntryError(
                                err,
                                "ExtendedKeyUsage".to_string(),
                            )
                        })?;

                    cert_builder
                        .sign(key_file, MessageDigest::sha256())
                        .map_err(|err: ErrorStack| {
                            X509Error::X509CertificateBuilerEntryError(err, "Sign".to_string())
                        })?;

                    return Ok((cert_builder.build(), Some(pkey)));
                }
                Err(err) => Err(X509Error::InitCARequestCertKeyPairError(err))?,
            }
        }
    }

    pub fn save_cert(cert: &X509, path: &str) -> X509Result<()> {
        let mut file: File = File::create(path)
            .map_err(|err: io::Error| X509Error::X509PEMFileCreationError(err))?;
        file.write_all(
            &cert
                .to_pem()
                .map_err(|err: ErrorStack| X509Error::PEMEncodingError(err))?,
        )
        .map_err(|err: io::Error| X509Error::X509WriteToFileError(err))?;
        Ok(())
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
