use crate::{
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
    fs,
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
) -> Result<(), Box<dyn std::error::Error>> {
    if request {
        for domain in &domains {
            let distinguished_name: DistinguishedName = DistinguishedName {
                common_name: commonname.clone(),
                organization: "Vanish".to_string(),
                country: country.clone(),
                state: state.clone(),
            };
            let ca_req_certificate: X509Req =
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
                let file_name: PathBuf = output_path.join(format!("{}.pem", domain));
                let file_name_str: Option<&str> = file_name.to_str();
                if let Some(file_name_str) = file_name_str {
                    CAReq::save_certificate_to_file(&ca_req_certificate, file_name_str)?;
                } else {
                    eprintln!("Error: Error creating file for domain : {}", domain);
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
                let leaf_certificate: X509 = LeafCert::generate_certificate(
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
                    let leaf_certificate: X509 =
                        LeafCert::generate_certificate(leaf_cert_object, &cert, &pkey, None)?;
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
                    } else {
                        let output_path: PathBuf = std::env::current_dir()?;
                        let file_name: PathBuf = output_path.join(format!("{}.pem", domain));
                        let file_name_str: Option<&str> = file_name.to_str();
                        if let Some(file_name_str) = file_name_str {
                            LeafCert::save_cert(&leaf_certificate, file_name_str)?;
                        } else {
                            eprintln!("Error: Error creating file for domain : {}", domain);
                        }
                    }
                }
            }
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
            let leaf_certificate: X509 = LeafCert::generate_certificate(
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
                let leaf_certificate: X509 =
                    LeafCert::generate_certificate(leaf_cert_object, &d_cert, &d_pkey, None)?;
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
                } else {
                    let output_path: PathBuf = std::env::current_dir()?;
                    let file_name: PathBuf = output_path.join(format!("{}.pem", domain));
                    let file_name_str: Option<&str> = file_name.to_str();
                    if let Some(file_name_str) = file_name_str {
                        LeafCert::save_cert(&leaf_certificate, file_name_str)?;
                    } else {
                        eprintln!("Error: Error creating file for domain : {}", domain);
                    }
                }
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
            let leaf_certificate: X509 = LeafCert::generate_certificate(
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
                let leaf_certificate: X509 = LeafCert::generate_certificate(
                    leaf_cert_object,
                    &created_cert,
                    &created_key,
                    None,
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
                    let file_name: PathBuf = output_path.join(format!("{}.pem", domain));
                    let file_name_str: Option<&str> = file_name.to_str();
                    if let Some(file_name_str) = file_name_str {
                        LeafCert::save_cert(&leaf_certificate, file_name_str)?;
                    } else {
                        eprintln!("Error: Error creating file for domain : {}", domain);
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
                }
            }
        }
    }

    Ok(())
}
