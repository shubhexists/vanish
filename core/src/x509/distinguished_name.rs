use super::errors::{X509Error, X509Result};
use openssl::{
    error::ErrorStack,
    x509::{X509Name, X509NameBuilder},
};

#[derive(Debug)]
pub struct DistinguishedName {
    common_name: Option<String>,
    organization: Option<String>,
    country: Option<String>,
    state: Option<String>,
    city: Option<String>,
}

impl DistinguishedName {
    pub fn distinguished_name_builder(self) -> X509Result<X509Name> {
        let mut x509_name: X509NameBuilder = X509NameBuilder::new()
            .map_err(|err: ErrorStack| X509Error::X509NameBuilderInitializeError(err))?;
        if let Some(common_name) = self.common_name {
            x509_name
                .append_entry_by_text("C", &common_name)
                .map_err(|err: ErrorStack| {
                    X509Error::X509NameBuilderEntryError(err, "C".to_string(), common_name)
                })?;
        }
        if let Some(organization) = self.organization {
            x509_name
                .append_entry_by_text("C", &organization)
                .map_err(|err: ErrorStack| {
                    X509Error::X509NameBuilderEntryError(err, "C".to_string(), organization)
                })?;
        }
        if let Some(country) = self.country {
            x509_name
                .append_entry_by_text("C", &country)
                .map_err(|err: ErrorStack| {
                    X509Error::X509NameBuilderEntryError(err, "C".to_string(), country)
                })?;
        }
        if let Some(state) = self.state {
            x509_name
                .append_entry_by_text("ST", &state)
                .map_err(|err: ErrorStack| {
                    X509Error::X509NameBuilderEntryError(err, "ST".to_string(), state)
                })?;
        }
        if let Some(city) = self.city {
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
