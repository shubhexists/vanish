use crate::errors::{CertKeyPairError, CertKeyResult};
use openssl::{
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
