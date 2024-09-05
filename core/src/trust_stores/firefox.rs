use colored::Colorize;

use super::errors::FirefoxTrustStoreError;
use std::borrow::Cow;
use std::process::{exit, Stdio};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};
pub struct FirefoxTrustStore {
    firefox_profile: Vec<String>,
    certutil_path: Option<String>,
    ca_unique_name: String,
    vanish_ca_path: String,
}

impl FirefoxTrustStore {
    pub fn new(
        ca_unique_name: String,
        vanish_ca_path: String,
    ) -> Result<FirefoxTrustStore, FirefoxTrustStoreError> {
        let mut firefox_profile: Vec<String> = Vec::<String>::new();
        let mut certutil_path: Option<String> = None;

        #[cfg(target_os = "linux")]
        {
            let home: String = env::var("HOME").map_err(|err: env::VarError| {
                FirefoxTrustStoreError::ENVVariableNotFound(err, "HOME".to_string())
            })?;
            firefox_profile.push(format!("{}/.mozilla/firefox", home));
            firefox_profile.push(format!("{}/snap/firefox/common/.mozilla/firefox", home));

            if Command::new("certutil").output().is_ok() {
                certutil_path = Some("certutil".to_string());
            }
        }

        #[cfg(target_os = "windows")]
        {
            let userprofile: String = env::var("USERPROFILE").map_err(|err: env::VarError| {
                FirefoxTrustStoreError::ENVVariableNotFound(err, "USERPROFILE".to_string())
            })?;
            firefox_profile.push(format!(
                "{}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles",
                userprofile
            ));

            // NOT SURE
            if Command::new("certutil").output().is_ok() {
                certutil_path = Some("certutil".to_string());
            }
        }

        #[cfg(target_os = "macos")]
        {
            let home: String = env::var("HOME").map_err(|err: env::VarError| {
                FirefoxTrustStoreError::ENVVariableNotFound(err, "HOME".to_string())
            })?;
            firefox_profile.push(format!(
                "{}/Library/Application Support/Firefox/Profiles/",
                home
            ));

            if Command::new("certutil").output().is_ok() {
                certutil_path = Some("certutil".to_string());
            } else if Path::new("/usr/local/opt/nss/bin/certutil").exists() {
                certutil_path = Some("/usr/local/opt/nss/bin/certutil".to_string());
            } else if let Ok(out) = Command::new("brew").arg("--prefix").arg("nss").output() {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let full_path = format!("{}/bin/certutil", path);
                if Path::new(&full_path).exists() {
                    certutil_path = Some(full_path);
                }
            }
        }

        Ok(FirefoxTrustStore {
            firefox_profile,
            certutil_path,
            vanish_ca_path,
            ca_unique_name,
        })
    }

    fn is_certificate_installed(&self, cert_dir: &Path) -> Result<bool, FirefoxTrustStoreError> {
        match &self.certutil_path {
            Some(certutil) => {
                let output = Command::new(certutil)
                    .arg("-L")
                    .arg("-d")
                    .arg(cert_dir.to_str().unwrap())
                    .output()
                    .map_err(|err: io::Error| FirefoxTrustStoreError::IOError(err))?;

                if output.status.success() {
                    let stdout: Cow<'_, str> = String::from_utf8_lossy(&output.stdout);

                    if stdout.contains(&self.ca_unique_name) {
                        return Ok(true);
                    }
                } else {
                    eprintln!(
                        "{}: Failed to list certificates in {:?}",
                        "Error".red(),
                        cert_dir
                    );
                }
            }
            None => {
                eprint!("{}: No certutil found. Please install!", "Error".red());
                exit(1);
            }
        }

        Ok(false)
    }

    pub fn find_cert_directories(&self) -> Result<Vec<PathBuf>, FirefoxTrustStoreError> {
        let mut cert_dirs: Vec<PathBuf> = Vec::new();
        for profile_dir in &self.firefox_profile {
            let path: &Path = Path::new(profile_dir);
            if path.exists() && path.is_dir() {
                for entry in fs::read_dir(path)
                    .map_err(|err: io::Error| FirefoxTrustStoreError::IOError(err))?
                {
                    let entry: fs::DirEntry =
                        entry.map_err(|err: io::Error| FirefoxTrustStoreError::IOError(err))?;
                    let entry_path: PathBuf = entry.path();
                    if entry_path.is_dir() {
                        let cert9_path: PathBuf = entry_path.join("cert9.db");
                        let cert8_path: PathBuf = entry_path.join("cert8.db");
                        if cert9_path.exists() || cert8_path.exists() {
                            cert_dirs.push(entry_path);
                        }
                    }
                }
            }
        }

        if cert_dirs.is_empty() {
            eprintln!("No directories containing certificate databases were found for any of your Firefox Profiles.");
            std::process::exit(1);
        } else {
            Ok(cert_dirs)
        }
    }

    pub fn install_firefox_certificates(&self, cert_paths: Vec<PathBuf>) {
        let all_installed: bool = cert_paths.iter().all(|cert_dir: &PathBuf| {
            match self.is_certificate_installed(cert_dir) {
                Ok(true) => true,
                Ok(false) => false,
                Err(_) => false,
            }
        });

        if all_installed {
            println!(
                "{}: Certificate already installed in all Firefox profiles ✅.",
                "Note".green()
            );
            return;
        } else {
            match &self.certutil_path {
                Some(path) => {
                    for cert_dir in cert_paths {
                        if let Ok(true) = self.is_certificate_installed(&cert_dir) {
                            continue;
                        }

                        let cmd_result: Result<ExitStatus, io::Error> = Command::new(path)
                            .arg("-A")
                            .arg("-d")
                            .arg(cert_dir.to_str().unwrap())
                            .arg("-t")
                            .arg("C,,")
                            .arg("-n")
                            .arg(&self.ca_unique_name)
                            .arg("-i")
                            .arg(&self.vanish_ca_path)
                            .stdout(Stdio::null())
                            .status();

                        match cmd_result {
                            Ok(_) => {}
                            Err(err) => {
                                eprintln!("{}: executing certutil: {:?}", "Error".red(), err);
                            }
                        }
                    }
                    println!("Certificate successfully installed in all Firefox profiles ✅.");
                }
                None => {
                    eprint!("No certutil found. Please install!");
                    exit(1);
                }
            };
        }
    }
}
