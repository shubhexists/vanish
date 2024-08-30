use super::{
    distinguished_name::DistinguishedName,
    errors::{X509Error, X509Result},
    Certificate, X509Version,
};
use crate::utils::{generate_cert_key_pair, generate_certificate_serial_number};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    error::ErrorStack,
    pkey::{PKey, Private},
    rsa::Rsa,
};

pub struct LeafCert {
    rsa_priv: Rsa<Private>,
    pkey: PKey<Private>,
    distinguished_name: DistinguishedName,
    version: X509Version,
    not_before: Asn1Time,
    not_after: Asn1Time,
    serial_number: Asn1Integer,
}

impl Certificate for LeafCert {
    fn new(distinguished_name: DistinguishedName) -> X509Result<Self> {
        match generate_cert_key_pair() {
            Ok((rsa_priv, pkey)) => match generate_certificate_serial_number() {
                Ok(serial_number) => {
                    let not_before: Asn1Time = Asn1Time::days_from_now(0)
                        .map_err(|err: ErrorStack| X509Error::GenerateNotBeforeError(err))?;
                    let not_after: Asn1Time = Asn1Time::days_from_now(365 * 2)
                        .map_err(|err: ErrorStack| X509Error::GenerateNotAfterError(err))?;
                    Ok(LeafCert {
                        rsa_priv,
                        pkey,
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
}
