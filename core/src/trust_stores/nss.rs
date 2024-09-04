use crate::trust_stores::nss_profile::NSSProfile;
use std::{
    fs, io,
    path::Path,
    process::{Command, ExitStatus},
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

    pub fn check_nss(&self) -> bool {
        if !self.profile.has_certutil {
            return false;
        }

        let mut success: bool = true;

        if self.for_each_nss_profile(|profile: &str| {
            println!("{:?}", self.profile.certutil_path);
            let cmd: Result<ExitStatus, io::Error> =
                Command::new(self.profile.certutil_path.as_ref().unwrap())
                    .arg("-V")
                    .arg("-d")
                    .arg(profile)
                    .arg("-u")
                    .arg("L")
                    .arg("-n")
                    .arg(&self.ca_unique_name)
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
        if self.for_each_nss_profile(|profile: &str| {
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
                    .status();

            if let Err(err) = cmd {
                eprintln!("Error: {:?}", err);
            }
        }) == 0
        {
            eprintln!("ERROR: no NSS security databases found");
            return false;
        }

        if !self.check_nss() {
            eprintln!(
                "Installing in NSS failed. Please report the issue with details about your environment."
            );
            return false;
        }

        true
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
        let profiles = &self.profile.nss_dbs;

        println!("{:?}", profiles);

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
