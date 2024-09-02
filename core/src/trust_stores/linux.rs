use openssl::error::ErrorStack;
use openssl::x509::X509;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::errors::TrustStoreError;

pub struct CAValue {
    pub certificate: X509,
}

impl CAValue {
    fn get_available_path() -> Option<PossibleStores> {
        let stores: [PossibleStores; 4] = [
            PossibleStores::RedHat,
            PossibleStores::Debian,
            PossibleStores::SuSE,
            PossibleStores::Other,
        ];

        for store in stores {
            if fs::metadata(store.get_path()).is_ok() {
                return Some(store);
            }
        }

        None
    }

    pub fn install_certificate(&self) -> Result<(), TrustStoreError> {
        let store: Option<PossibleStores> = CAValue::get_available_path();
        match store {
            Some(store) => {
                let path: String = store.get_path();
                println!("Adding file to trust store: {}", path);
                let pem_path: PathBuf = Path::new(&path).join("vanish-root.crt");

                if let Err(err) = fs::create_dir_all(&path) {
                    eprintln!("Failed to create directory: {}. Error: {}", path, err);
                    return Err(TrustStoreError::PEMFileCreationError(err));
                }

                match CAValue::save_cert(&self.certificate, pem_path.to_str().unwrap()) {
                    Ok(_) => println!("Certificate saved at: {}", pem_path.display()),
                    Err(err) => eprintln!("Failed to save certificate: {}", err),
                }
            }
            None => {
                eprintln!("Your system is not supported by Vanish yet.");
            }
        }

        Ok(())
    }

    fn save_cert(cert: &X509, path: &str) -> Result<(), TrustStoreError> {
        let mut file: File = File::create(path)
            .map_err(|err: io::Error| TrustStoreError::PEMFileCreationError(err))?;
        file.write_all(
            &cert
                .to_pem()
                .map_err(|err: ErrorStack| TrustStoreError::PEMEncodingError(err))?,
        )
        .map_err(|err: io::Error| TrustStoreError::WriteToFileError(err))?;
        Ok(())
    }
}

enum PossibleStores {
    RedHat,
    Debian,
    SuSE,
    Other,
}

impl PossibleStores {
    fn get_path(&self) -> String {
        match self {
            PossibleStores::RedHat => "/etc/pki/ca-trust/source/anchors/".to_string(),
            PossibleStores::Debian => "/usr/local/share/ca-certificates/".to_string(),
            PossibleStores::SuSE => "/etc/ca-certificates/trust-source/anchors/".to_string(),
            PossibleStores::Other => "/usr/share/pki/trust/anchors/".to_string(),
        }
    }
}