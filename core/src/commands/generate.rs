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
use openssl::{
    pkey::{PKey, Private},
    x509::{X509Req, X509},
};
use std::error;

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
            let distinguished_name: DistinguishedName =
                create_distinguished_name(&commonname, &country, &state);
            let (ca_req_certificate, private_key) =
                CAReq::new(distinguished_name)?.generate_certificate()?;
            save_csr_certificate(domain.to_string(), &output, ca_req_certificate, private_key)?;
        }
        return Ok(());
    }

    if let Some(certfile) = certfile {
        if let Some(keyfile) = keyfile {
            let (cert, pkey) = CACert::load_ca_cert(&certfile, &keyfile)?;
            if let Some(csr) = &csr {
                let distinguished_name: DistinguishedName =
                    create_distinguished_name(&commonname, &country, &state);
                let csr_object: X509Req = CAReq::read_csr_from_file(csr)?;
                let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                let (leaf_certificate, _private_key) = LeafCert::generate_certificate(
                    leaf_cert_object,
                    &cert,
                    &pkey,
                    Some(&csr_object),
                )?;
                save_pem_certificate("csr_cert.pem".to_string(), output, leaf_certificate)?;
            } else {
                for domain in &domains {
                    let distinguished_name: DistinguishedName =
                        create_distinguished_name(&commonname, &country, &state);
                    let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                    let (leaf_certificate, private_key) =
                        LeafCert::generate_certificate(leaf_cert_object, &cert, &pkey, None)?;
                    if let Some(private_key) = private_key {
                        save_pem_key_pair(
                            &output,
                            leaf_certificate,
                            domain.to_string(),
                            private_key,
                        )?;
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
            let distinguished_name: DistinguishedName =
                create_distinguished_name(&commonname, &country, &state);
            let csr_object: X509Req = CAReq::read_csr_from_file(csr)?;
            let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
            let (leaf_certificate, _private_key) = LeafCert::generate_certificate(
                leaf_cert_object,
                &d_cert,
                &d_pkey,
                Some(&csr_object),
            )?;
            save_pem_certificate("csr_cert.pem".to_string(), output, leaf_certificate)?;
        } else {
            for domain in &domains {
                let distinguished_name: DistinguishedName =
                    create_distinguished_name(&commonname, &country, &state);
                let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                let (leaf_certificate, private_key) =
                    LeafCert::generate_certificate(leaf_cert_object, &d_cert, &d_pkey, None)?;
                if let Some(private_key) = private_key {
                    save_pem_key_pair(&output, leaf_certificate, domain.to_string(), private_key)?;
                } else {
                    eprintln!(
                        "Oops! We lost your private key for domain {}. Please try again!",
                        domain
                    )
                }
            }
        }

        if install {
            generate_install(d_cert)?;
        }
    } else {
        if noca {
            eprintln!("Error: No CA Certificates found and generation of a new one is disabled by `--no-ca`");
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
            let (leaf_certificate, _private_key) = LeafCert::generate_certificate(
                leaf_cert_object,
                &created_cert,
                &created_key,
                Some(&csr_object),
            )?;
            save_pem_certificate("csr_cert.pem".to_string(), output, leaf_certificate)?;
        } else {
            for domain in &domains {
                let distinguished_name: DistinguishedName =
                    create_distinguished_name(&commonname, &country, &state);
                let leaf_cert_object: LeafCert = LeafCert::new(distinguished_name)?;
                let (leaf_certificate, private_key) = LeafCert::generate_certificate(
                    leaf_cert_object,
                    &created_cert,
                    &created_key,
                    None,
                )?;
                if let Some(private_key) = private_key {
                    save_pem_key_pair(&output, leaf_certificate, domain.to_string(), private_key)?;
                } else {
                    eprintln!(
                        "Oops! We lost your private key for domain {}. Please try again!",
                        domain
                    )
                }
            }
        }
        if install {
            generate_install(created_cert)?;
        }
    }
    Ok(())
}
