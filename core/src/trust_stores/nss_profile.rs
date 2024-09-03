use std::path::{Path, PathBuf};
use std::process::Command;

pub struct NSSProfile {
    pub has_nss: bool,
    pub has_certutil: bool,
    pub certutil_path: Option<String>,
    pub nss_dbs: Vec<String>,
    pub firefox_paths: Vec<String>,
}

impl NSSProfile {
    pub fn new() -> Self {
        let nss_dbs: Vec<String> = vec![
            dirs::home_dir()
                .map(|p| p.join(".pki/nssdb"))
                .unwrap_or_else(|| PathBuf::new())
                .to_str()
                .unwrap()
                .to_string(),
            dirs::home_dir()
                .map(|p| p.join("snap/chromium/current/.pki/nssdb"))
                .unwrap_or_else(|| PathBuf::new())
                .to_str()
                .unwrap()
                .to_string(),
            "/etc/pki/nssdb".to_string(),
        ];

        let firefox_paths: Vec<String> = vec![
            "/usr/bin/firefox".to_string(),
            "/usr/bin/firefox-nightly".to_string(),
            "/usr/bin/firefox-developer-edition".to_string(),
            "/snap/firefox".to_string(),
            "/Applications/Firefox.app".to_string(),
            "/Applications/FirefoxDeveloperEdition.app".to_string(),
            "/Applications/Firefox Developer Edition.app".to_string(),
            "/Applications/Firefox Nightly.app".to_string(),
            "C:\\Program Files\\Mozilla Firefox".to_string(),
        ];

        let mut has_nss: bool = false;
        let all_paths: Vec<String> = [&nss_dbs[..], &firefox_paths[..]].concat();
        for path in &all_paths {
            if Path::new(path).exists() {
                has_nss = true;
                break;
            }
        }

        let mut has_certutil: bool = false;
        let mut certutil_path: Option<String> = None;

        if cfg!(target_os = "macos") {
            if Command::new("certutil").output().is_ok() {
                certutil_path = Some("certutil".to_string());
                has_certutil = true;
            } else if Path::new("/usr/local/opt/nss/bin/certutil").exists() {
                certutil_path = Some("/usr/local/opt/nss/bin/certutil".to_string());
                has_certutil = true;
            } else if let Ok(out) = Command::new("brew").arg("--prefix").arg("nss").output() {
                let path: String = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let full_path: String = format!("{}/bin/certutil", path);
                if Path::new(&full_path).exists() {
                    certutil_path = Some(full_path);
                    has_certutil = true;
                }
            }
        } else if cfg!(target_os = "linux") {
            if Command::new("certutil").output().is_ok() {
                certutil_path = Some("certutil".to_string());
                has_certutil = true;
            }
        }

        Self {
            has_nss,
            has_certutil,
            certutil_path,
            nss_dbs,
            firefox_paths,
        }
    }

    pub fn path_exists(path: &str) -> bool {
        Path::new(path).exists()
    }
}
