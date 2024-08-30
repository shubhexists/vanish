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

// later
trait Certificate {}
