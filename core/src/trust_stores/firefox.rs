use super::errors::FirefoxTrustStoreError;
use std::process::exit;
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

    pub fn find_cert_directories(&self) -> Result<Vec<PathBuf>, FirefoxTrustStoreError> {
        let mut cert_dirs: Vec<PathBuf> = Vec::new();
        println!("Firefox Profiles: {:?}", &self.firefox_profile);
        for profile_dir in &self.firefox_profile {
            let path: &Path = Path::new(profile_dir);
            println!("{:?} exists: {:?}", &path, &path.exists());
            if path.exists() && path.is_dir() {
                println!("Path is a dir: {:?}", &path);
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
        match &self.certutil_path {
            Some(path) => {
                for cert_dir in cert_paths {
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
                        .status();

                    match cmd_result {
                        Ok(status) if status.success() => {
                            println!("Successfully installed certificate in {:?}", cert_dir);
                        }
                        Ok(_) => {
                            eprintln!("Failed to install certificate in {:?}", cert_dir);
                        }
                        Err(err) => {
                            eprintln!("Error executing certutil: {:?}", err);
                        }
                    }
                }
            }
            None => {
                eprint!("No certutil found. Please install!");
                exit(1);
            }
        };
    }
}
