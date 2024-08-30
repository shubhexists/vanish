use super::errors::{X509Error, X509Result};
use openssl::{
    error::ErrorStack,
    x509::{X509Name, X509NameBuilder},
};

#[derive(Debug)]
pub struct DistinguishedName {
    common_name: String,
    organization: String,
    country: Option<String>,
    state: Option<String>,
    city: Option<String>,
}

impl DistinguishedName {
    pub fn distinguished_name_builder(distinguished_name: Self) -> X509Result<X509Name> {
        let mut x509_name: X509NameBuilder = X509NameBuilder::new()
            .map_err(|err: ErrorStack| X509Error::X509NameBuilderInitializeError(err))?;
        x509_name
            .append_entry_by_text("CN", &distinguished_name.common_name)
            .map_err(|err: ErrorStack| {
                X509Error::X509NameBuilderEntryError(
                    err,
                    "CN".to_string(),
                    distinguished_name.common_name.clone(),
                )
            })?;
        x509_name
            .append_entry_by_text("O", &distinguished_name.common_name)
            .map_err(|err: ErrorStack| {
                X509Error::X509NameBuilderEntryError(
                    err,
                    "O".to_string(),
                    distinguished_name.organization,
                )
            })?;
        if let Some(country) = distinguished_name.country {
            x509_name
                .append_entry_by_text("C", &country)
                .map_err(|err: ErrorStack| {
                    X509Error::X509NameBuilderEntryError(err, "C".to_string(), country)
                })?;
        }
        if let Some(state) = distinguished_name.state {
            x509_name
                .append_entry_by_text("ST", &state)
                .map_err(|err: ErrorStack| {
                    X509Error::X509NameBuilderEntryError(err, "ST".to_string(), state)
                })?;
        }
        if let Some(city) = distinguished_name.city {
            x509_name
                .append_entry_by_text("L", &city)
                .map_err(|err: ErrorStack| {
                    X509Error::X509NameBuilderEntryError(err, "L".to_string(), city)
                })?;
        }
        let x509_name: X509Name = x509_name.build();
        Ok(x509_name)
    }
}
