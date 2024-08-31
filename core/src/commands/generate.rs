use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::x509::{
    ca_cert::CACert, ca_req::CAReq, distinguished_name::DistinguishedName, leaf_cert::LeafCert,
    Certificate,
};
use openssl::x509::{X509Req, X509};

pub fn generate(
    domains: Vec<String>,
    noca: bool,
    debug: bool,
    csr: Option<String>,
    certfile: Option<String>,
    keyfile: Option<String>,
    organization: Option<String>,
    country: Option<String>,
    commonname: Option<String>,
    state: Option<String>,
    output: Option<String>,
    request: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if request {
        // ONLY CSR (CA Not Required)
        for domain in &domains {
            let distinguished_name: DistinguishedName = DistinguishedName {
                common_name: commonname.clone(),
                organization: organization.clone(),
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
            // No need to check for files as load_ca_cert handles and throws X509 Error
            let (cert, pkey) = CACert::load_ca_cert(&certfile, &keyfile)?;
            if let Some(csr) = &csr {
                let distinguished_name: DistinguishedName = DistinguishedName {
                    common_name: commonname.clone(),
                    organization: organization.clone(),
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
                // Save File
            } else {
                for domain in &domains {
                    let distinguished_name: DistinguishedName = DistinguishedName {
                        // replace to domain_name
                        common_name: commonname.clone(),
                        organization: organization.clone(),
                        country: country.clone(),
                        state: state.clone(),
                    };
                    let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                    let leaf_certificate: X509 =
                        LeafCert::generate_certificate(leaf_cert_object, &cert, &pkey, None)?;
                    // Save file
                }
            }
            return Ok(());
        } else {
            eprintln!("Corresponding KeyFile Not Found");
            std::process::exit(1);
        }
    }

    // Check for CA files in default path

    // If Not CA Cert/Key Found
    if noca {
        // Error - noca and no Cert/Found
    }
    // Create CA
    if csr.is_some() {
        // Use Created CA and CSR to Generate
    }
    for domain in &domains {}

    // Found
    if csr.is_some() {
        // Use Found CA and CSR to Generate
    }
    for domain in domains {}

    Ok(())
}
