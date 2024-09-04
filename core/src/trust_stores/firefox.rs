use super::errors::FirefoxTrustStoreError;
use std::{
    env, ffi, fs, io,
    path::{Path, PathBuf},
};

pub struct FirefoxTrustStore {
    firefox_profile: Vec<String>,
}

impl FirefoxTrustStore {
    pub fn new() -> Result<FirefoxTrustStore, FirefoxTrustStoreError> {
        let mut firefox_profile: Vec<String> = Vec::<String>::new();
        #[cfg(target_os = "linux")]
        {
            let home: String = env::var("HOME").map_err(|err: env::VarError| {
                FirefoxTrustStoreError::ENVVariableNotFound(err, "HOME".to_string())
            })?;
            firefox_profile.push(home.clone() + "/.morzilla/firefox/");
            firefox_profile.push(home + "/snap/firefox/common/.mozilla/firefox/");
        }
        #[cfg(target_os = "windows")]
        {
            let userprofile: String = env::var("USERPROFILE").map_err(|err: env::VarError| {
                FirefoxTrustStoreError::ENVVariableNotFound(err, "USERPROFILE".to_string())
            })?;
            firefox_profile.push(userprofile + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles");
        }
        #[cfg(target_os = "macos")]
        {
            let home: String = env::var("HOME").map_err(|err: env::VarError| {
                FirefoxTrustStoreError::ENVVariableNotFound(err, "HOME".to_string())
            })?;
            firefox_profile.push(home + "/Library/Application Support/Firefox/Profiles/");
        }
        Ok(FirefoxTrustStore { firefox_profile })
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

    pub fn install_firefox_certificates(&self) {}
}
