use distinguished_name::DistinguishedName;
use errors::X509Result;
use lazy_static::lazy_static;
use std::path::PathBuf;
pub mod ca_cert;
pub mod ca_req;
mod distinguished_name;
mod errors;
pub mod leaf_cert;

lazy_static! {
    static ref DATA_DIR: Option<PathBuf> = dirs::data_dir().map(|path| path.join("vanish"));
}

#[derive(Debug)]
#[allow(dead_code)]
enum X509Version {
    V1 = 0,
    V2 = 1,
    V3 = 2,
}

pub trait Certificate {
    type Output;
    fn new(distinguished_name: DistinguishedName) -> X509Result<Self>
    where
        Self: Sized;
    fn generate_certificate(self) -> X509Result<Self::Output>;
}
