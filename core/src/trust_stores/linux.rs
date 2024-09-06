use super::errors::TrustStoreError;
use colored::*;
use openssl::error::ErrorStack;
use openssl::x509::X509;
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

pub struct CAValue {
    pub ca_uniques_name: String,
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

    fn is_certificate_installed(&self, pem_path: &Path) -> bool {
        if pem_path.exists() {
            println!(
                "{}: Certificate already exists in {}",
                "Info".blue(),
                pem_path.display()
            );
            true
        } else {
            false
        }
    }

    pub fn install_certificate(&self) -> Result<(), TrustStoreError> {
        let store: Option<PossibleStores> = CAValue::get_available_path();
        match store {
            Some(store) => {
                let path: String = store.get_path();
                let pem_path: PathBuf =
                    Path::new(&path).join(format!("ca_{}.pem", self.ca_uniques_name));

                if self.is_certificate_installed(&pem_path) {
                    println!("{}: Certificate already installed  ✅.", "Info".blue(),);
                    return Ok(());
                }

                self.write_certificate_with_tee(&pem_path)?;

                self.run_update_certs_command(store);
            }
            None => {
                eprintln!("Your system is not supported by Vanish yet.");
            }
        }

        Ok(())
    }

    fn write_certificate_with_tee(&self, pem_path: &Path) -> Result<(), TrustStoreError> {
        let cert_pem = self
            .certificate
            .to_pem()
            .map_err(|err: ErrorStack| TrustStoreError::PEMEncodingError(err))?;

        let mut tee_cmd = Command::new("sudo")
            .arg("tee")
            .arg(pem_path.to_str().unwrap())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .map_err(|err: io::Error| {
                TrustStoreError::CommandError(format!(
                    "{}: Failed to run sudo tee: {}",
                    "Error".red(),
                    err
                ))
            })?;

        tee_cmd
            .stdin
            .as_mut()
            .ok_or(TrustStoreError::CommandError(
                "Failed to open tee stdin".to_string(),
            ))?
            .write_all(&cert_pem)
            .map_err(|err: io::Error| {
                TrustStoreError::PEMFileCreationError(io::Error::new(io::ErrorKind::Other, err))
            })?;

        let status = tee_cmd.wait().map_err(|err| {
            TrustStoreError::CommandError(format!(
                "{}: Failed to wait for tee: {}",
                "Error".red(),
                err
            ))
        })?;

        if !status.success() {
            return Err(TrustStoreError::CommandError(
                "Tee command failed".to_string(),
            ));
        }

        Ok(())
    }

    fn run_update_certs_command(&self, store: PossibleStores) {
        let (cmd, arg) = match store {
            PossibleStores::RedHat => ("sudo", "update-ca-trust"),
            PossibleStores::Debian => ("sudo", "update-ca-certificates"),
            PossibleStores::SuSE => ("sudo", "update-ca-certificates"),
            _ => return,
        };

        let output: Result<ExitStatus, io::Error> =
            Command::new(cmd).arg(arg).stdout(Stdio::null()).status();

        match output {
            Ok(status) if status.success() => {
                println!("{}: {} completed successfully", "Success".green(), arg)
            }
            Ok(_) => eprintln!(
                "{}: {} failed. Please try running the command with elevated permissions.",
                "Error".red(),
                arg
            ),
            Err(err) => eprintln!("{}: Failed to run {}: {:?}", "Error".red(), arg, err),
        }
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
