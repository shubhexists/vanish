use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
use openssl::x509::{X509Builder, X509NameBuilder, X509Req, X509};
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;

fn main() {
    // hardcoded paths for now
    let ca_cert_path = "./ca-cert.pem";
    let ca_key_path = "./ca-key.pem";

    // CA CERTIFICATE
    // If keys exist on those paths, load the keys otherwise simply generate a new one
    let (ca_cert, ca_key) = if !Path::new(ca_cert_path).exists() || !Path::new(ca_key_path).exists()
    {
        println!("Creating a new CA certificate...");
        generate_ca(ca_cert_path, ca_key_path)
    } else {
        println!("Loading existing CA certificate...");
        load_ca(ca_cert_path, ca_key_path)
    };

    // END ENTITY / LEAF CERTIFICATE

    // After loading the keys, generate certificate with those keys, currently hardcoding the domain to localhost
    let cert = generate_certificate(&ca_cert, &ca_key, "localhost").unwrap();
    // Save the certificate value to a hardcoded file for now
    save_certificate(&cert, "./localhost.pem").unwrap();
}

fn generate_ca(cert_path: &str, key_path: &str) -> (X509, PKey<Private>) {
    // generates a RSA Private key
    let rsa = Rsa::generate(2048).unwrap();
    // generates a public key from the above generated private key
    let pkey = PKey::from_rsa(rsa).unwrap();

    // Creating a X.509 Object

    // THIS IS THE DISTINGUISHED NAME PART OF THE OBJECT
    /* OPTIONS
       - O - Organization
       - CN - Common Name for the Org ( Ideally, For SSL/TLS it should be domain names and otherwise Individual )
       - C - Country
    */
    let mut name = X509NameBuilder::new().unwrap();
    // C not added currently will add a option later on
    name.append_entry_by_text("O", "what should I name it lol? ")
        .unwrap();
    name.append_entry_by_text("CN", "Shubham Singh").unwrap();
    // Finally built the name
    let name = name.build();

    let mut builder: openssl::x509::X509Builder = X509::builder().unwrap();

    // Latest Version is 3 only that is in RFC 3280
    builder.set_version(2).unwrap();

    // Since this is a self signed certificate, we have subject name ans issuer name to be the same
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();

    builder.set_pubkey(&pkey).unwrap();

    // Adding NOT SET BEFORE AND NOT SET AFTER
    let not_before: Asn1Time = Asn1Time::days_from_now(0).unwrap();
    let not_after: Asn1Time = Asn1Time::days_from_now(365 * 10).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    let serial_number: openssl::asn1::Asn1Integer =
        BigNum::from_u32(0).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial_number).unwrap();

    // BasicConstraints::new sets us a builder for constaints and ca specifies that this is a CA certificate
    builder
        .append_extension(BasicConstraints::new().ca().build().unwrap())
        .unwrap();

    // signs the entire certificate that is generated with the Private key that we generated
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let cert = builder.build();
    save_certificate(&cert, cert_path).unwrap();
    save_key(&pkey, key_path).unwrap();

    (cert, pkey)
}

// just returns CA Cert and CA Key
fn load_ca(cert_path: &str, key_path: &str) -> (X509, PKey<Private>) {
    let cert = X509::from_pem(&std::fs::read(cert_path).unwrap()).unwrap();
    let key = PKey::private_key_from_pem(&std::fs::read(key_path).unwrap()).unwrap();
    (cert, key)
}

// fn generate_certificate_from_csr() {
//     let csr_path = "whatever the path is";
//     let mut csr_file = File::open(csr_path).expect("Unable to open CSR file");
//     let mut csr_pem = String::new();
//     csr_file
//         .read_to_string(&mut csr_pem)
//         .expect("Unable to read CSR file");

//     // taken from examples # https://docs.rs/x509-parser/latest/x509_parser/pem/index.html#examples

//     // let pem = Pem::parse_x509(csr_pem.as_bytes()).expect("Failed to parse PEM");
// }

fn generate_certificate(
    ca_cert: &X509,
    ca_key: &PKey<Private>,
    common_name: &str,
) -> Result<X509, Box<dyn std::error::Error>> {
    // RSA Private Key
    let rsa = Rsa::generate(2048)?;
    // Public key from that private key
    let pkey = PKey::from_rsa(rsa)?;

    // REPEATED
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", common_name)?;
    let name = name.build();

    let mut builder = X509::builder()?;
    builder.set_version(2)?;

    builder.set_subject_name(&name)?;
    builder.set_issuer_name(ca_cert.subject_name())?;
    builder.set_pubkey(&pkey)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365 * 2)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    let serial_number = BigNum::from_u32(1)?.to_asn1_integer()?;
    builder.set_serial_number(&serial_number)?;

    // -----------------

    // PROVIDING PERMISSIONS

    builder.append_extension(
        KeyUsage::new()
            .digital_signature() // tells that this key can be used to create digital signatures
            .key_encipherment() //
            .build()?,
    )?;
    // extendedKeyUsage is also similar to Key Usage....
    builder.append_extension(
        ExtendedKeyUsage::new()
            .server_auth() // Used in SSL/TLS
            .client_auth() // Client Auth used in Mutual TLS
            .build()?,
    )?;

    // Sign leaf key with the CA Key
    builder.sign(ca_key, MessageDigest::sha256())?;

    Ok(builder.build())
}

fn save_certificate(cert: &X509, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;
    file.write_all(&cert.to_pem()?)?;
    Ok(())
}

// TO SEE - What is PKCS#8 ( mkcert refers something like PKCS#12)
fn save_key(key: &PKey<Private>, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;
    file.write_all(&key.private_key_to_pem_pkcs8()?)?;
    Ok(())
}

fn generate_csr() -> Result<X509Req, Box<dyn std::error::Error>> {
    let rsa: Rsa<Private> = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "Some-State")?;
    x509_name.append_entry_by_text("L", "Some-City")?;
    x509_name.append_entry_by_text("O", "Example Organization")?;
    x509_name.append_entry_by_text("CN", "example.com")?;
    let x509_name: openssl::x509::X509Name = x509_name.build();

    let mut csr = X509Req::builder()?;
    csr.set_subject_name(&x509_name)?;
    csr.set_pubkey(&pkey)?;
    csr.sign(&pkey, openssl::hash::MessageDigest::sha256())?;

    let csr = csr.build();

    Ok(csr)
}

fn save_csr_to_file(csr: &X509Req, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let csr_pem = csr.to_pem()?;
    let mut file = File::create(filename)?;
    file.write_all(&csr_pem);

    println!("CSR saved to {}", filename);

    Ok(())
}

// fn main() {
//     match generate_csr() {
//         Ok(csr) => {
//             if let Err(e) = save_csr_to_file(&csr, "example_csr.pem") {
//                 eprintln!("Failed to save CSR: {}", e);
//             }
//         }
//         Err(e) => eprintln!("Failed to generate CSR: {}", e),
//     }
// }

fn read_csr_from_file(filename: &str) -> Result<X509Req, Box<dyn std::error::Error>> {
    let mut file = File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let csr = X509Req::from_pem(&buffer)?;
    Ok(csr)
}

fn generate_certificate_from_CSR_Req(
    ca_cert: &X509,
    ca_key: &PKey<Private>,
    csr: &X509Req,
) -> Result<X509, Box<dyn std::error::Error>> {
    // Extract the public key and subject name from the CSR
    let pkey = csr.public_key()?;
    let subject_name = csr.subject_name();

    // Create a new certificate builder
    let mut builder: X509Builder = X509Builder::new()?;
    builder.set_version(2)?;

    builder.set_subject_name(subject_name)?;
    builder.set_issuer_name(ca_cert.subject_name())?;
    builder.set_pubkey(&pkey)?;

    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(365 * 2)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;

    let serial_number = BigNum::from_u32(1)?.to_asn1_integer()?;
    builder.set_serial_number(&serial_number)?;

    // Set the key usage and extended key usage
    builder.append_extension(
        KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    builder.append_extension(
        ExtendedKeyUsage::new()
            .server_auth()
            .client_auth()
            .build()?,
    )?;

    // Sign the certificate with the CA key
    builder.sign(ca_key, MessageDigest::sha256())?;

    Ok(builder.build())
}

// fn main() {
//     // Assuming `ca_cert.pem` and `ca_key.pem` are your CA's certificate and private key files
//     let ca_cert = X509::from_pem(&std::fs::read("ca_cert.pem").unwrap()).unwrap();
//     let ca_key = PKey::private_key_from_pem(&std::fs::read("ca_key.pem").unwrap()).unwrap();

//     // Read CSR from file
//     let csr = read_csr_from_file("example_csr.pem").expect("Failed to read CSR");

//     // Generate a certificate based on the CSR
//     match generate_certificate(&ca_cert, &ca_key, &csr) {
//         Ok(cert) => {
//             let cert_pem = cert.to_pem().unwrap();
//             std::fs::write("signed_cert.pem", cert_pem).expect("Failed to write certificate");
//             println!("Certificate generated and saved to signed_cert.pem");
//         }
//         Err(e) => eprintln!("Failed to generate certificate: {}", e),
//     }
// }
