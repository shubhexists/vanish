use super::nss_profile::NSSProfile;
use crate::trust_stores::errors::NSSStore;
use openssl::x509::X509;
use std::io::{self, Write};
use std::path::PathBuf;
use std::{
    fs::{self, File},
    path::Path,
    process::Command,
};

pub struct NSSValue {
    pub certificate: X509,
}

impl NSSValue {
    fn get_available_profile() -> Option<NSSProfile> {
        let profiles: [NSSProfile; 3] = [
            NSSProfile::PkiNssdb,
            NSSProfile::ChromiumNssdb,
            NSSProfile::Firefox,
        ];

        for profile in profiles {
            if let Some(_path) = profile.get_valid_path() {
                return Some(profile);
            }
        }

        None
    }

    pub fn install_certificate(&self) -> Result<(), NSSStore> {
        if let Some(profile) = NSSValue::get_available_profile() {
            if let Some(path) = profile.get_valid_path() {
                println!("Adding certificate to NSS profile: {}", path.display());
                let pem_path: PathBuf = Path::new(&path).join("vanish-root.crt");

                if let Err(err) = fs::create_dir_all(&path) {
                    eprintln!(
                        "Failed to create directory: {}. Error: {}",
                        path.display(),
                        err
                    );
                    return Err(NSSStore::PEMFileCreationError(err));
                }

                NSSValue::save_cert(&self.certificate, pem_path.to_str().unwrap())?;
                NSSValue::run_certutil(&pem_path, &path)?;
            }
        } else {
            eprintln!("No valid NSS profile found.");
            return Err(NSSStore::NSSProfileNotFound);
        }

        Ok(())
    }

    fn save_cert(cert: &X509, path: &str) -> Result<(), NSSStore> {
        let mut file: File = File::create(path).map_err(NSSStore::PEMFileCreationError)?;
        file.write_all(&cert.to_pem().map_err(NSSStore::PEMEncodingError)?)
            .map_err(NSSStore::WriteToFileError)?;
        Ok(())
    }

    fn run_certutil(cert_path: &Path, profile_path: &Path) -> Result<(), NSSStore> {
        let status = Command::new("certutil")
            .arg("-A")
            .arg("-d")
            .arg(format!("sql:{}", profile_path.display()))
            .arg("-t")
            .arg("C,,")
            .arg("-n")
            .arg("vanish-root")
            .arg("-i")
            .arg(cert_path)
            .status()
            .map_err(|err: io::Error| NSSStore::CertUtilFailed(err.to_string()))?;

        if !status.success() {
            return Err(NSSStore::CertUtilFailed("certutil command failed".into()));
        }

        Ok(())
    }
}
