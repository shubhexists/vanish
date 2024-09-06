use crate::trust_stores::nss_profile::NSSProfile;
use colored::*;
use std::{
    borrow::Cow,
    fs, io,
    path::Path,
    process::{exit, Command, ExitStatus, Stdio},
};

pub struct NSSValue {
    pub profile: NSSProfile,
    pub ca_unique_name: String,
    pub caroot: String,
}

impl NSSValue {
    pub fn new(profile: NSSProfile, ca_unique_name: String, caroot: String) -> Self {
        Self {
            profile,
            ca_unique_name,
            caroot,
        }
    }

    fn is_certificate_installed(&self, cert_dir: &Path) -> Result<bool, io::Error> {
        match &self.profile.certutil_path {
            Some(certutil) => {
                let output = Command::new(certutil)
                    .arg("-L")
                    .arg("-d")
                    .arg(cert_dir.to_str().unwrap())
                    .output()
                    .map_err(|err: io::Error| err)?;

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

    pub fn check_nss(&self) -> bool {
        if !self.profile.has_certutil {
            return false;
        }

        let mut success: bool = true;

        if self.for_each_nss_profile(|profile: &str| {
            let cmd: Result<ExitStatus, io::Error> =
                Command::new(self.profile.certutil_path.as_ref().unwrap())
                    .arg("-V")
                    .arg("-d")
                    .arg(profile)
                    .arg("-u")
                    .arg("L")
                    .arg("-n")
                    .arg(&self.ca_unique_name)
                    .stdout(Stdio::null())
                    .status();

            if cmd.is_err() || !cmd.unwrap().success() {
                success = false;
            }
        }) == 0
        {
            success = false;
        }

        success
    }

    pub fn install_nss(&self) -> bool {
        let mut all_installed: bool = true;
        let mut any_installed: bool = false;

        self.for_each_nss_profile(|profile: &str| {
            let cert_dir = Path::new(profile);
            if let Ok(installed) = self.is_certificate_installed(cert_dir) {
                if installed {
                    any_installed = true;
                } else {
                    all_installed = false;
                }
            } else {
                all_installed = false;
            }
        });

        if all_installed {
            println!(
                "{}: Certificate already installed in all NSS (Browser) profiles ✅.",
                "Info".blue()
            );
            return true;
        }

        let installed: bool = self.for_each_nss_profile(|profile: &str| {
            let cert_dir = Path::new(profile);
            if let Ok(installed) = self.is_certificate_installed(cert_dir) {
                if !installed {
                    let cmd: Result<ExitStatus, io::Error> =
                        Command::new(self.profile.certutil_path.as_ref().unwrap())
                            .arg("-A")
                            .arg("-d")
                            .arg(profile)
                            .arg("-t")
                            .arg("C,,")
                            .arg("-n")
                            .arg(&self.ca_unique_name)
                            .arg("-i")
                            .arg(&self.caroot)
                            .stdout(Stdio::null())
                            .status();

                    if let Err(err) = cmd {
                        eprintln!("Error installing in profile {}: {:?}", profile, err);
                    }
                }
            }
        }) > 0;

        if installed && self.check_nss() {
            println!("Certificate successfully installed in all NSS (Browser) profiles ✅.");
            return true;
        } else {
            eprintln!("{}: Installing in NSS failed. Please report the issue with details about your environment.", "Error".red());
            return false;
        }
    }

    pub fn _uninstall_nss(&self) {
        self.for_each_nss_profile(|profile: &str| {
            let cmd: Result<ExitStatus, io::Error> =
                Command::new(self.profile.certutil_path.as_ref().unwrap())
                    .arg("-D")
                    .arg("-d")
                    .arg(profile)
                    .arg("-n")
                    .arg(&self.ca_unique_name)
                    .stdout(Stdio::null())
                    .status();

            if let Err(err) = cmd {
                eprintln!("Error: {:?}", err);
            }
        });
    }

    fn for_each_nss_profile<F>(&self, mut f: F) -> usize
    where
        F: FnMut(&str),
    {
        let mut found: usize = 0;
        let profiles: &Vec<String> = &self.profile.nss_dbs;

        for profile in profiles {
            let stat: Result<fs::Metadata, io::Error> = Path::new(profile).metadata();
            if stat.is_ok() && stat.unwrap().is_dir() {
                if NSSProfile::path_exists(&format!("{}/cert9.db", profile)) {
                    f(&format!("sql:{}", profile));
                    found += 1;
                } else if NSSProfile::path_exists(&format!("{}/cert8.db", profile)) {
                    f(&format!("dbm:{}", profile));
                    found += 1;
                }
            }
        }

        found
    }
}
