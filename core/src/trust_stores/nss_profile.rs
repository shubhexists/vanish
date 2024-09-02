use std::path::{Path, PathBuf};

pub enum NSSProfile {
    PkiNssdb,
    ChromiumNssdb,
    Firefox,
}

impl NSSProfile {
    pub fn get_valid_path(&self) -> Option<PathBuf> {
        match self {
            NSSProfile::PkiNssdb => {
                let path: PathBuf = dirs::home_dir()?.join(".pki/nssdb");
                if path.exists() {
                    Some(path)
                } else {
                    None
                }
            }
            NSSProfile::ChromiumNssdb => {
                let path: PathBuf = dirs::home_dir()?.join("snap/chromium/current/.pki/nssdb");
                if path.exists() {
                    Some(path)
                } else {
                    None
                }
            }
            NSSProfile::Firefox => {
                let firefox_paths: [&str; 9] = [
                    "/usr/bin/firefox",
                    "/usr/bin/firefox-nightly",
                    "/usr/bin/firefox-developer-edition",
                    "/snap/firefox",
                    "/Applications/Firefox.app",
                    "/Applications/FirefoxDeveloperEdition.app",
                    "/Applications/Firefox Developer Edition.app",
                    "/Applications/Firefox Nightly.app",
                    "C:\\Program Files\\Mozilla Firefox",
                ];

                for path in firefox_paths.iter() {
                    let profile_path: &Path = Path::new(path);
                    if profile_path.exists() {
                        return Some(profile_path.to_path_buf());
                    }
                }
                None
            }
        }
    }
}
