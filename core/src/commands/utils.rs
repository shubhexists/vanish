use crate::{
    trust_stores::{
        firefox::FirefoxTrustStore, nss::NSSValue, nss_profile::NSSProfile,
        utils::check_if_firefox_exists, CAValue,
    },
    x509::{ca_req::CAReq, distinguished_name::DistinguishedName, leaf_cert::LeafCert},
};
use openssl::{
    pkey::{PKey, Private},
    x509::{X509Req, X509},
};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
};

pub fn generate_install(cert: X509) -> Result<(), Box<dyn Error>> {
    let ca_value_object: CAValue = CAValue { certificate: cert };
    ca_value_object.install_certificate()?;
    let nss_profile_object: NSSProfile = NSSProfile::new();
    let ca_unique_name: String = "vanish-root-test-123456-shubham-brr".to_string();
    let caroot: String = "/home/jerry/.local/share/vanish/ca_cert.pem".to_string();
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
        println!("Certificate installed successfully.");
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
            LeafCert::save_cert(&leaf_certificate, file_name_str)?;
        } else {
            eprintln!("Error: Error creating file for generated Certificate :");
        }
    } else {
        let output_path: PathBuf = std::env::current_dir()?;
        let file_name: PathBuf = output_path.join("csr_cert.pem");
        let file_name_str: Option<&str> = file_name.to_str();
        if let Some(file_name_str) = file_name_str {
            LeafCert::save_cert(&leaf_certificate, file_name_str)?;
        } else {
            eprintln!("Error: Error creating file for generated Certificate");
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
        let file_name: PathBuf = output_path.join("csr_cert.pem");
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
        let file_name: PathBuf = output_path.join("csr_cert.pem");
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
    } else {
        let output_path: PathBuf = std::env::current_dir()?;
        let file_name: PathBuf = output_path.join(format!("{}.pem", name));
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
    }
    Ok(())
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
