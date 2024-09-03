use crate::{
    trust_stores::{nss::NSSValue, nss_profile::NSSProfile, CAValue},
    utils::{get_certificates_from_data_dir, save_generated_cert_key_files},
    x509::{
        ca_cert::CACert, ca_req::CAReq, distinguished_name::DistinguishedName, leaf_cert::LeafCert,
        Certificate,
    },
};
use openssl::{
    pkey::{PKey, Private},
    x509::{X509Req, X509},
};
use std::{
    error, fs,
    path::{Path, PathBuf},
};

pub fn generate(
    domains: Vec<String>,
    noca: bool,
    csr: Option<String>,
    certfile: Option<String>,
    keyfile: Option<String>,
    country: Option<String>,
    commonname: Option<String>,
    state: Option<String>,
    output: Option<String>,
    request: bool,
    install: bool,
) -> Result<(), Box<dyn error::Error>> {
    if request {
        for domain in &domains {
            let distinguished_name: DistinguishedName = DistinguishedName {
                common_name: commonname.clone(),
                organization: "Vanish".to_string(),
                country: country.clone(),
                state: state.clone(),
            };
            let (ca_req_certificate, private_key) =
                CAReq::new(distinguished_name)?.generate_certificate()?;
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
                let file_name: PathBuf = output_path.join(format!("csr-{}.pem", domain));
                let file_name_str: Option<&str> = file_name.to_str();
                if let Some(file_name_str) = file_name_str {
                    CAReq::save_certificate_to_file(&ca_req_certificate, file_name_str)?;
                } else {
                    eprintln!("Error: Error creating file for domain : {}", domain);
                }
                let key_file_name: PathBuf = output_path.join(format!("csr-{}-key.pem", domain));
                let key_file_name_str: Option<&str> = key_file_name.to_str();
                if let Some(key_file_name_str) = key_file_name_str {
                    CAReq::save_key(&private_key, key_file_name_str)?;
                } else {
                    eprintln!("Error: Error creating file for key : {}", domain);
                }
            } else {
                let output_path: PathBuf = std::env::current_dir()?;
                let file_name: PathBuf = output_path.join(format!("{}.pem", domain));
                let file_name_str: Option<&str> = file_name.to_str();
                if let Some(file_name_str) = file_name_str {
                    CAReq::save_certificate_to_file(&ca_req_certificate, file_name_str)?;
                } else {
                    eprintln!("Error: Error creating file for domain : {}", domain);
                }
                let key_file_name: PathBuf = output_path.join(format!("csr-{}-key.pem", domain));
                let key_file_name_str: Option<&str> = key_file_name.to_str();
                if let Some(key_file_name_str) = key_file_name_str {
                    CAReq::save_key(&private_key, key_file_name_str)?;
                } else {
                    eprintln!("Error: Error creating file for key : {}", domain);
                }
            }
        }
        return Ok(());
    }

    if let Some(certfile) = certfile {
        if let Some(keyfile) = keyfile {
            let (cert, pkey) = CACert::load_ca_cert(&certfile, &keyfile)?;
            if let Some(csr) = &csr {
                let distinguished_name: DistinguishedName = DistinguishedName {
                    common_name: commonname.clone(),
                    organization: "Vanish".to_string(),
                    country: country.clone(),
                    state: state.clone(),
                };
                let csr_object: X509Req = CAReq::read_csr_from_file(csr)?;
                let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                let (leaf_certificate, _private_key) = LeafCert::generate_certificate(
                    leaf_cert_object,
                    &cert,
                    &pkey,
                    Some(&csr_object),
                )?;
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
                } else {
                    let output_path: PathBuf = std::env::current_dir()?;
                    let file_name: PathBuf = output_path.join("csr_cert.pem");
                    let file_name_str: Option<&str> = file_name.to_str();
                    if let Some(file_name_str) = file_name_str {
                        LeafCert::save_cert(&leaf_certificate, file_name_str)?;
                    } else {
                        eprintln!("Error: Error creating file for generated Certificate :");
                    }
                }
            } else {
                for domain in &domains {
                    let distinguished_name: DistinguishedName = DistinguishedName {
                        common_name: Some(domain.to_string()),
                        organization: "Vanish".to_string(),
                        country: country.clone(),
                        state: state.clone(),
                    };
                    let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                    let (leaf_certificate, private_key) =
                        LeafCert::generate_certificate(leaf_cert_object, &cert, &pkey, None)?;
                    if let Some(private_key) = private_key {
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
                            let file_name: PathBuf = output_path.join(format!("{}.pem", domain));
                            let file_name_str: Option<&str> = file_name.to_str();
                            if let Some(file_name_str) = file_name_str {
                                LeafCert::save_cert(&leaf_certificate, file_name_str)?;
                            } else {
                                eprintln!("Error: Error creating file for domain : {}", domain);
                            }
                            let key_file_name: PathBuf =
                                output_path.join(format!("{}-key.pem", domain));
                            let key_file_name_str: Option<&str> = key_file_name.to_str();
                            if let Some(key_file_name_str) = key_file_name_str {
                                LeafCert::save_key(&private_key, key_file_name_str)?;
                            } else {
                                eprintln!("Error: Error creating file for key : {}", domain);
                            }
                        } else {
                            let output_path: PathBuf = std::env::current_dir()?;
                            let file_name: PathBuf = output_path.join(format!("{}.pem", domain));
                            let file_name_str: Option<&str> = file_name.to_str();
                            if let Some(file_name_str) = file_name_str {
                                LeafCert::save_cert(&leaf_certificate, file_name_str)?;
                            } else {
                                eprintln!("Error: Error creating file for domain : {}", domain);
                            }
                            let key_file_name: PathBuf =
                                output_path.join(format!("{}-key.pem", domain));
                            let key_file_name_str: Option<&str> = key_file_name.to_str();
                            if let Some(key_file_name_str) = key_file_name_str {
                                LeafCert::save_key(&private_key, key_file_name_str)?;
                            } else {
                                eprintln!("Error: Error creating file for key : {}", domain);
                            }
                        }
                    } else {
                        eprintln!(
                            "Oops! We lost your private key for domain {}. Please try again!",
                            domain
                        )
                    }
                }
            }
            if install {}
            return Ok(());
        } else {
            eprintln!("Corresponding KeyFile Not Found");
            std::process::exit(1);
        }
    }

    let default_cert_key_files: Option<(X509, PKey<Private>)> = get_certificates_from_data_dir();
    if let Some((d_cert, d_pkey)) = default_cert_key_files {
        if let Some(csr) = &csr {
            let distinguished_name: DistinguishedName = DistinguishedName {
                common_name: commonname.clone(),
                organization: "Vanish".to_string(),
                country: country.clone(),
                state: state.clone(),
            };
            let csr_object: X509Req = CAReq::read_csr_from_file(csr)?;
            let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
            let (leaf_certificate, _private_key) = LeafCert::generate_certificate(
                leaf_cert_object,
                &d_cert,
                &d_pkey,
                Some(&csr_object),
            )?;
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
            } else {
                let output_path: PathBuf = std::env::current_dir()?;
                let file_name: PathBuf = output_path.join("csr_cert.pem");
                let file_name_str: Option<&str> = file_name.to_str();
                if let Some(file_name_str) = file_name_str {
                    LeafCert::save_cert(&leaf_certificate, file_name_str)?;
                } else {
                    eprintln!("Error: Error creating file for generated Certificate :");
                }
            }
        } else {
            for domain in &domains {
                let distinguished_name: DistinguishedName = DistinguishedName {
                    common_name: Some(domain.to_string()),
                    organization: "Vanish".to_string(),
                    country: country.clone(),
                    state: state.clone(),
                };
                let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                let (leaf_certificate, private_key) =
                    LeafCert::generate_certificate(leaf_cert_object, &d_cert, &d_pkey, None)?;
                if let Some(private_key) = private_key {
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
                        let file_name: PathBuf = output_path.join(format!("{}.pem", domain));
                        let file_name_str: Option<&str> = file_name.to_str();
                        if let Some(file_name_str) = file_name_str {
                            LeafCert::save_cert(&leaf_certificate, file_name_str)?;
                        } else {
                            eprintln!("Error: Error creating file for domain : {}", domain);
                        }
                        let key_file_name: PathBuf =
                            output_path.join(format!("{}-key.pem", domain));
                        let key_file_name_str: Option<&str> = key_file_name.to_str();
                        if let Some(key_file_name_str) = key_file_name_str {
                            LeafCert::save_key(&private_key, key_file_name_str)?;
                        } else {
                            eprintln!("Error: Error creating file for key : {}", domain);
                        }
                    } else {
                        let output_path: PathBuf = std::env::current_dir()?;
                        let file_name: PathBuf = output_path.join(format!("{}.pem", domain));
                        let file_name_str: Option<&str> = file_name.to_str();
                        if let Some(file_name_str) = file_name_str {
                            LeafCert::save_cert(&leaf_certificate, file_name_str)?;
                        } else {
                            eprintln!("Error: Error creating file for domain : {}", domain);
                        }
                        let key_file_name: PathBuf =
                            output_path.join(format!("{}-key.pem", domain));
                        let key_file_name_str: Option<&str> = key_file_name.to_str();
                        if let Some(key_file_name_str) = key_file_name_str {
                            LeafCert::save_key(&private_key, key_file_name_str)?;
                        } else {
                            eprintln!("Error: Error creating file for key : {}", domain);
                        }
                    }
                } else {
                    eprintln!(
                        "Oops! We lost your private key for domain {}. Please try again!",
                        domain
                    )
                }
            }
        }

        if install {
            let ca_value_object: CAValue = CAValue {
                certificate: d_cert,
            };
            ca_value_object.install_certificate()?;
            let nss_profile_object: NSSProfile = NSSProfile::new();
            let ca_unique_name = "vanish-root-test-123456-ujjwal".to_string();
            let caroot = "/home/jerry/.local/share/vanish/ca_cert.pem".to_string();
            let mkcert = NSSValue::new(nss_profile_object, ca_unique_name, caroot);
            let success = mkcert.install_nss();

            if success {
                println!("Certificate installed successfully.");
            } else {
                eprintln!("Failed to install the certificate.");
            }
        }
    } else {
        if noca {
            eprintln!("Error: No CA Certificates found and generation of a new one is disabled by `--no-ca`");
            std::process::exit(1)
        }
        // Replace with correct variables
        let distinguished_name: DistinguishedName = DistinguishedName {
            common_name: commonname.clone(),
            organization: "Vanish".to_string(),
            country: country.clone(),
            state: state.clone(),
        };
        let (created_cert, created_key) =
            CACert::new(distinguished_name)?.generate_certificate()?;
        save_generated_cert_key_files(&created_cert, &created_key)?;
        if let Some(csr) = &csr {
            let distinguished_name: DistinguishedName = DistinguishedName {
                common_name: commonname.clone(),
                organization: "Vanish".to_string(),
                country: country.clone(),
                state: state.clone(),
            };
            let csr_object: X509Req = CAReq::read_csr_from_file(csr)?;
            let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
            let (leaf_certificate, _private_key) = LeafCert::generate_certificate(
                leaf_cert_object,
                &created_cert,
                &created_key,
                Some(&csr_object),
            )?;
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
            } else {
                let output_path: PathBuf = std::env::current_dir()?;
                let file_name: PathBuf = output_path.join("csr_cert.pem");
                let file_name_str: Option<&str> = file_name.to_str();
                if let Some(file_name_str) = file_name_str {
                    LeafCert::save_cert(&leaf_certificate, file_name_str)?;
                } else {
                    eprintln!("Error: Error creating file for generated Certificate :");
                }
            }
        } else {
            for domain in &domains {
                let distinguished_name: DistinguishedName = DistinguishedName {
                    common_name: Some(domain.to_string()),
                    organization: "Vanish".to_string(),
                    country: country.clone(),
                    state: state.clone(),
                };
                let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                let (leaf_certificate, private_key) = LeafCert::generate_certificate(
                    leaf_cert_object,
                    &created_cert,
                    &created_key,
                    None,
                )?;
                if let Some(private_key) = private_key {
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
                        let file_name: PathBuf = output_path.join(format!("{}.pem", domain));
                        let file_name_str: Option<&str> = file_name.to_str();
                        if let Some(file_name_str) = file_name_str {
                            LeafCert::save_cert(&leaf_certificate, file_name_str)?;
                        } else {
                            eprintln!("Error: Error creating file for domain : {}", domain);
                        }
                        let key_file_name: PathBuf =
                            output_path.join(format!("{}-key.pem", domain));
                        let key_file_name_str: Option<&str> = key_file_name.to_str();
                        if let Some(key_file_name_str) = key_file_name_str {
                            LeafCert::save_key(&private_key, key_file_name_str)?;
                        } else {
                            eprintln!("Error: Error creating file for key : {}", domain);
                        }
                    } else {
                        let output_path: PathBuf = std::env::current_dir()?;
                        let file_name: PathBuf = output_path.join(format!("{}.pem", domain));
                        let file_name_str: Option<&str> = file_name.to_str();
                        if let Some(file_name_str) = file_name_str {
                            LeafCert::save_cert(&leaf_certificate, file_name_str)?;
                        } else {
                            eprintln!("Error: Error creating file for domain : {}", domain);
                        }
                        let key_file_name: PathBuf =
                            output_path.join(format!("{}-key.pem", domain));
                        let key_file_name_str: Option<&str> = key_file_name.to_str();
                        if let Some(key_file_name_str) = key_file_name_str {
                            LeafCert::save_key(&private_key, key_file_name_str)?;
                        } else {
                            eprintln!("Error: Error creating file for key : {}", domain);
                        }
                    }
                } else {
                    eprintln!(
                        "Oops! We lost your private key for domain {}. Please try again!",
                        domain
                    )
                }
            }
        }
        if install {
            let ca_value_object: CAValue = CAValue {
                certificate: created_cert,
            };
            ca_value_object.install_certificate()?;
            let nss_profile_object: NSSProfile = NSSProfile::new();
            let ca_unique_name: String = "vanish-root-testing-1234-ujjwal".to_string();
            let caroot: String = "/home/jerry/.local/share/vanish/ca_cert.pem".to_string();
            let mkcert: NSSValue = NSSValue::new(nss_profile_object, ca_unique_name, caroot);
            let success: bool = mkcert.install_nss();

            if success {
                println!("Certificate installed successfully.");
            } else {
                eprintln!("Failed to install the certificate.");
            }
        }
    }

    Ok(())
}
