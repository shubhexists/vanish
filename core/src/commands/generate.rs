use super::utils::{
    create_distinguished_name, generate_install, save_csr_certificate, save_pem_certificate,
    save_pem_key_pair,
};
use crate::{
    utils::{get_certificates_from_data_dir, save_generated_cert_key_files},
    x509::{
        ca_cert::CACert, ca_req::CAReq, distinguished_name::DistinguishedName, leaf_cert::LeafCert,
        Certificate,
    },
};
use colored::*;
use openssl::{
    pkey::{PKey, Private},
    x509::{X509Req, X509},
};
use std::{
    error::{self, Error},
    path::PathBuf,
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
    println!();
    if request {
        println!("Generated Certificate Requests for :");
        for domain in &domains {
            let distinguished_name: DistinguishedName =
                create_distinguished_name(&commonname, &country, &state);
            let (ca_req_certificate, private_key) =
                CAReq::new(distinguished_name)?.generate_certificate()?;
            let is_saved: Result<PathBuf, Box<dyn Error>> =
                save_csr_certificate(domain.to_string(), &output, ca_req_certificate, private_key);
            match is_saved {
                Ok(path) => {
                    println!("   - \"{}\" ✅", domain);
                    println!();
                    println!(
                        "{}: Your request certs and their corresponding keys are saved at: {:?}",
                        "Note".green(),
                        path
                    );
                }
                Err(_err) => {
                    println!("   - \"{}\" ❌", domain);
                }
            }
        }
        println!();
        return Ok(());
    }

    if let Some(certfile) = certfile {
        if let Some(keyfile) = keyfile {
            let (cert, pkey) = match CACert::load_ca_cert(&certfile, &keyfile) {
                Ok(cert_pkey) => cert_pkey,
                Err(err) => {
                    eprintln!("{}", err);
                    std::process::exit(1);
                }
            };
            if let Some(csr) = &csr {
                let distinguished_name: DistinguishedName =
                    create_distinguished_name(&commonname, &country, &state);
                let csr_object: X509Req = match CAReq::read_csr_from_file(csr) {
                    Ok(csr) => csr,
                    Err(err) => {
                        eprintln!("{}", err);
                        std::process::exit(1);
                    }
                };
                let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                println!();
                let (leaf_certificate, _private_key) = match LeafCert::generate_certificate(
                    leaf_cert_object,
                    &cert,
                    &pkey,
                    Some(&csr_object),
                ) {
                    Ok((a, b)) => {
                        println!("Generating Certificate for Signing Request Successful! 👍");
                        (a, b)
                    }
                    Err(err) => {
                        println!("Generating Certificate for Signing Request Failed! 👎");
                        eprintln!("{}", err);
                        std::process::exit(1);
                    }
                };
                match save_pem_certificate("csr_cert.pem".to_string(), output, leaf_certificate) {
                    Ok(()) => {}
                    Err(err) => {
                        println!("{}", err);
                        std::process::exit(1);
                    }
                };
            } else {
                println!();
                println!("Generated Certificate for : ");
                for domain in &domains {
                    let distinguished_name: DistinguishedName =
                        create_distinguished_name(&commonname, &country, &state);
                    let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                    let (leaf_certificate, private_key) = match LeafCert::generate_certificate(
                        leaf_cert_object,
                        &cert,
                        &pkey,
                        None,
                    ) {
                        Ok((a, b)) => {
                            println!("   - \"{}\" ✅", domain);
                            (a, b)
                        }
                        Err(err) => {
                            println!("   - \"{}\" ❌", domain);
                            eprintln!("{}", err);
                            std::process::exit(1);
                        }
                    };
                    if let Some(private_key) = private_key {
                        match save_pem_key_pair(
                            &output,
                            leaf_certificate,
                            domain.to_string(),
                            private_key,
                        ) {
                            Ok(()) => {}
                            Err(err) => {
                                println!("{}", err);
                            }
                        };
                    } else {
                        eprintln!(
                            "{}{}{}",
                            "Oops! We lost your private key for domain ".yellow(),
                            domain.yellow(),
                            ". Please try again!".yellow()
                        )
                    }
                }
                println!();
                println!(
                    "{}: All Successful Certificates and their corresponding keys are saved at : {}",
                    "Note".green(),
                    output.unwrap()
                );
            }
            if install {}
            println!();
            return Ok(());
        } else {
            eprintln!("{}: Corresponding KeyFile Not Found", "Error".red());
            println!();
            std::process::exit(1);
        }
    }

    let default_cert_key_files: Option<(X509, PKey<Private>)> = get_certificates_from_data_dir();
    if let Some((d_cert, d_pkey)) = default_cert_key_files {
        if let Some(csr) = &csr {
            let distinguished_name: DistinguishedName =
                create_distinguished_name(&commonname, &country, &state);
            let csr_object: X509Req = CAReq::read_csr_from_file(csr)?;
            let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
            println!();
            let (leaf_certificate, _private_key) = match LeafCert::generate_certificate(
                leaf_cert_object,
                &d_cert,
                &d_pkey,
                Some(&csr_object),
            ) {
                Ok((a, b)) => {
                    println!("Generating Certificate for Signing Request Successful! 👍");
                    (a, b)
                }
                Err(err) => {
                    println!("Generating Certificate for Signing Request Failed! 👎");
                    eprintln!("{}", err);
                    std::process::exit(1);
                }
            };
            save_pem_certificate("csr_cert.pem".to_string(), output, leaf_certificate)?;
        } else {
            println!();
            println!("Generated Certificate for : ");
            for domain in &domains {
                let distinguished_name: DistinguishedName =
                    create_distinguished_name(&commonname, &country, &state);
                let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                let (leaf_certificate, private_key) = match LeafCert::generate_certificate(
                    leaf_cert_object,
                    &d_cert,
                    &d_pkey,
                    None,
                ) {
                    Ok((a, b)) => {
                        println!("   - \"{}\" ✅", domain);
                        (a, b)
                    }
                    Err(err) => {
                        println!("   - \"{}\" ❌", domain);
                        eprintln!("{}", err);
                        std::process::exit(1);
                    }
                };
                if let Some(private_key) = private_key {
                    save_pem_key_pair(&output, leaf_certificate, domain.to_string(), private_key)?;
                } else {
                    eprintln!(
                        "Oops! We lost your private key for domain {}. Please try again!",
                        domain
                    )
                }
            }
            println!();
            println!(
                "{}: All Successful Certificates and their corresponding keys are saved at : {}",
                "Note".green(),
                output.unwrap()
            );
        }

        if install {
            generate_install(d_cert)?;
        }
    } else {
        if noca {
            eprintln!(
                "{}: No CA Certificates found and generation of a new one is disabled by `--no-ca`",
                "Error".red()
            );
            std::process::exit(1)
        }
        let distinguished_name: DistinguishedName =
            create_distinguished_name(&commonname, &country, &state);
        let (created_cert, created_key) =
            CACert::new(distinguished_name)?.generate_certificate()?;
        save_generated_cert_key_files(&created_cert, &created_key)?;
        if let Some(csr) = &csr {
            let distinguished_name: DistinguishedName =
                create_distinguished_name(&commonname, &country, &state);
            let csr_object: X509Req = CAReq::read_csr_from_file(csr)?;
            let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
            println!();
            let (leaf_certificate, _private_key) = match LeafCert::generate_certificate(
                leaf_cert_object,
                &created_cert,
                &created_key,
                Some(&csr_object),
            ) {
                Ok((a, b)) => {
                    println!("Generating Certificate for Signing Request Successful! 👍");
                    (a, b)
                }
                Err(err) => {
                    println!("Generating Certificate for Signing Request Failed! 👎");
                    eprintln!("{}", err);
                    std::process::exit(1);
                }
            };
            save_pem_certificate("csr_cert.pem".to_string(), output, leaf_certificate)?;
        } else {
            println!();
            println!("Generated Certificate for : ");
            for domain in &domains {
                let distinguished_name: DistinguishedName =
                    create_distinguished_name(&commonname, &country, &state);
                let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                let (leaf_certificate, private_key) = match LeafCert::generate_certificate(
                    leaf_cert_object,
                    &created_cert,
                    &created_key,
                    None,
                ) {
                    Ok((a, b)) => {
                        println!("   - \"{}\" ✅", domain);
                        (a, b)
                    }
                    Err(err) => {
                        println!("   - \"{}\" ❌", domain);
                        eprintln!("{}", err);
                        std::process::exit(1);
                    }
                };
                if let Some(private_key) = private_key {
                    match save_pem_key_pair(
                        &output,
                        leaf_certificate,
                        domain.to_string(),
                        private_key,
                    ) {
                        Ok(()) => {}
                        Err(err) => {
                            println!("{}", err);
                        }
                    };
                } else {
                    eprintln!(
                        "{}{}{}",
                        "Oops! We lost your private key for domain ".yellow(),
                        domain.yellow(),
                        ". Please try again!".yellow()
                    )
                }
            }

            println!();
            println!(
                "{}: All Successful Certificates and their corresponding keys are saved at : {}",
                "Note".green(),
                output.unwrap()
            );
        }
        if install {
            generate_install(created_cert)?;
        }
    }
    println!();
    Ok(())
}
