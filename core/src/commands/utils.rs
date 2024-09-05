use crate::{
    trust_stores::{
        firefox::FirefoxTrustStore, nss::NSSValue, nss_profile::NSSProfile,
        utils::check_if_firefox_exists, CAValue,
    },
    utils::get_unique_hash,
    x509::{ca_req::CAReq, distinguished_name::DistinguishedName, leaf_cert::LeafCert},
};
use colored::*;
use openssl::{
    pkey::{PKey, Private},
    x509::{X509Req, X509},
};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

pub fn generate_install(cert: &X509) -> Result<(), Box<dyn Error>> {
    let ca_value_object: CAValue = CAValue {
        certificate: cert.clone(),
    };
    ca_value_object.install_certificate()?;
    let nss_profile_object: NSSProfile = NSSProfile::new();
    let caroot: String = "/home/jerry/.local/share/vanish/ca_cert.pem".to_string();
    let ca_unique_name: String = get_unique_hash(&caroot)?;
    let mkcert: NSSValue =
        NSSValue::new(nss_profile_object, ca_unique_name.clone(), caroot.clone());
    let success: bool = mkcert.install_nss();
    let firefox_exists: bool = check_if_firefox_exists()?;
    if firefox_exists {
        let firefox_trust_store_object: FirefoxTrustStore =
            FirefoxTrustStore::new(ca_unique_name, caroot)?;
        let paths_with_trust_stores: Vec<PathBuf> =
            FirefoxTrustStore::find_cert_directories(&firefox_trust_store_object)?;
        FirefoxTrustStore::install_firefox_certificates(
            &firefox_trust_store_object,
            paths_with_trust_stores,
        );
    }
    if success {
        println!("Certificate installed successfully 👍");
    } else {
        eprintln!("Failed to install the certificate.");
    }
    Ok(())
}

pub fn save_pem_certificate(
    name: String,
    output: Option<String>,
    leaf_certificate: X509,
) -> Result<(), Box<dyn Error>> {
    if let Some(output) = &output {
        let output_path: &Path = Path::new(output);
        if !output_path.exists() {
            fs::create_dir_all(output_path)?;
        }
        let output_path: PathBuf = if output_path.is_absolute() {
            output_path.to_path_buf()
        } else {
            std::env::current_dir()?.join(output_path)
        };
        let file_name: PathBuf = output_path.join(name);
        let file_name_str: Option<&str> = file_name.to_str();
        if let Some(file_name_str) = file_name_str {
            match LeafCert::save_cert(&leaf_certificate, file_name_str) {
                Ok(()) => {
                    println!();
                    println!(
                        "{}: Your local certificate from request is saved at: {:?}",
                        "Note".green(),
                        file_name
                    );
                    println!(
                        "{}: You may use the Private Key of the Certificate Provided as the Private Key of your Local Certificate.",
                        "Note".green()
                    );
                }
                Err(err) => {
                    eprintln!("{}", err);
                }
            };
        } else {
            eprintln!(
                "{}: Error creating file for Generated Certificate :",
                "Error".red()
            );
        }
    } else {
        let output_path: PathBuf = std::env::current_dir()?;
        let file_name: PathBuf = output_path.join("csr_cert.pem");
        let file_name_str: Option<&str> = file_name.to_str();
        if let Some(file_name_str) = file_name_str {
            match LeafCert::save_cert(&leaf_certificate, file_name_str) {
                Ok(()) => {
                    println!();
                    println!(
                        "{}: Your local certificate from request is saved at: {:?}",
                        "Note".green(),
                        file_name
                    );
                    println!(
                        "{}: You may use the Private Key of the Certificate Provided as the Private Key of your Local Certificate.",
                        "Note".green()
                    );
                }
                Err(err) => {
                    eprintln!("{}", err);
                }
            };
        } else {
            eprintln!(
                "{}: Error creating file for Generated Certificate",
                "Error".red()
            );
        }
    }
    Ok(())
}

pub fn save_pem_key_pair(
    output: &Option<String>,
    leaf_certificate: X509,
    name: String,
    private_key: PKey<Private>,
) -> Result<(), Box<dyn Error>> {
    if let Some(output) = &output {
        let output_path: &Path = Path::new(output);
        if !output_path.exists() {
            fs::create_dir_all(output_path)?;
        }
        let output_path: PathBuf = if output_path.is_absolute() {
            output_path.to_path_buf()
        } else {
            std::env::current_dir()?.join(output_path)
        };
        let file_name: PathBuf = output_path.join(format!("{}.pem", name));
        let file_name_str: Option<&str> = file_name.to_str();
        if let Some(file_name_str) = file_name_str {
            LeafCert::save_cert(&leaf_certificate, file_name_str)?;
        } else {
            eprintln!("Error: Error creating file for generated Certificate :");
        }
        let key_file_name: PathBuf = output_path.join(format!("{}-key.pem", name));
        let key_file_name_str: Option<&str> = key_file_name.to_str();
        if let Some(key_file_name_str) = key_file_name_str {
            LeafCert::save_key(&private_key, key_file_name_str)?;
        } else {
            eprintln!("Error: Error creating file for key : {}", name);
        }
    } else {
        let output_path: PathBuf = std::env::current_dir()?;
        let file_name: PathBuf = output_path.join(format!("{}.pem", name));
        let file_name_str: Option<&str> = file_name.to_str();
        if let Some(file_name_str) = file_name_str {
            LeafCert::save_cert(&leaf_certificate, file_name_str)?;
        } else {
            eprintln!("Error: Error creating file for generated Certificate");
        }
        let key_file_name: PathBuf = output_path.join(format!("{}-key.pem", name));
        let key_file_name_str: Option<&str> = key_file_name.to_str();
        if let Some(key_file_name_str) = key_file_name_str {
            LeafCert::save_key(&private_key, key_file_name_str)?;
        } else {
            eprintln!("Error: Error creating file for key : {}", name);
        }
    }
    Ok(())
}

pub fn save_csr_certificate(
    name: String,
    output: &Option<String>,
    ca_req_certificate: X509Req,
    private_key: PKey<Private>,
) -> Result<PathBuf, Box<dyn Error>> {
    if let Some(output) = &output {
        let output_path: &Path = Path::new(output);
        if !output_path.exists() {
            fs::create_dir_all(output_path)?;
        }
        let output_path: PathBuf = if output_path.is_absolute() {
            output_path.to_path_buf()
        } else {
            std::env::current_dir()?.join(output_path)
        };
        let file_name: PathBuf = output_path.join(format!("csr-{}.pem", name));
        let file_name_str: Option<&str> = file_name.to_str();
        if let Some(file_name_str) = file_name_str {
            CAReq::save_certificate_to_file(&ca_req_certificate, file_name_str)?;
        } else {
            eprintln!("Error: Error creating file for domain : {}", name);
        }
        let key_file_name: PathBuf = output_path.join(format!("csr-{}-key.pem", name));
        let key_file_name_str: Option<&str> = key_file_name.to_str();
        if let Some(key_file_name_str) = key_file_name_str {
            CAReq::save_key(&private_key, key_file_name_str)?;
        } else {
            eprintln!("Error: Error creating file for key : {}", name);
        }
        return Ok(output_path);
    } else {
        let output_path: PathBuf = std::env::current_dir()?;
        let file_name: PathBuf = output_path.join(format!("csr-{}.pem", name));
        let file_name_str: Option<&str> = file_name.to_str();
        if let Some(file_name_str) = file_name_str {
            CAReq::save_certificate_to_file(&ca_req_certificate, file_name_str)?;
        } else {
            eprintln!("Error: Error creating file for domain : {}", name);
        }
        let key_file_name: PathBuf = output_path.join(format!("csr-{}-key.pem", name));
        let key_file_name_str: Option<&str> = key_file_name.to_str();
        if let Some(key_file_name_str) = key_file_name_str {
            CAReq::save_key(&private_key, key_file_name_str)?;
        } else {
            eprintln!("Error: Error creating file for key : {}", name);
        }
        Ok(output_path)
    }
}

pub fn create_distinguished_name(
    commonname: &Option<String>,
    country: &Option<String>,
    state: &Option<String>,
) -> DistinguishedName {
    DistinguishedName {
        common_name: commonname.clone(),
        organization: "Vanish".to_string(),
        country: country.clone(),
        state: state.clone(),
    }
}
