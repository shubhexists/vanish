// use super::errors::TrustStoreError;
// use colored::*;
// use openssl::error::ErrorStack;
// use openssl::x509::{X509Name, X509};
// use plist::{self, Value};
// use std::collections::HashMap;
// use std::fs::{self, File};
// use std::io::{self, Read, Write};
// use std::path::{Path, PathBuf};
// use std::process::{Command, Stdio};
// use tempfile::NamedTempFile;

// pub struct CAValue {
//     pub ca_uniques_name: String,
//     pub certificate: X509,
// }

// impl CAValue {
//     pub fn install_certificate(&self) -> Result<(), TrustStoreError> {
//         let cert_path = self.get_cert_path()?;
//         if self.is_certificate_installed(&cert_path) {
//             println!("{}: Certificate already installed ✅", "Info".blue());
//             return Ok(());
//         }

//         self.write_certificate_with_tee(&cert_path)?;
//         self.update_trust_settings(&cert_path)?;

//         println!("{}: Certificate installed successfully!", "Success".green());
//         Ok(())
//     }

//     fn get_cert_path(&self) -> Result<PathBuf, TrustStoreError> {
//         let root_name = format!("ca_{}.pem", self.ca_uniques_name);
//         let path = Path::new("/Library/Keychains/System.keychain").join(&root_name);
//         Ok(path)
//     }

//     fn is_certificate_installed(&self, pem_path: &Path) -> bool {
//         if pem_path.exists() {
//             println!(
//                 "{}: Certificate already exists in {}",
//                 "Info".blue(),
//                 pem_path.display()
//             );
//             true
//         } else {
//             false
//         }
//     }

//     fn write_certificate_with_tee(&self, pem_path: &Path) -> Result<(), TrustStoreError> {
//         let cert_pem = self
//             .certificate
//             .to_pem()
//             .map_err(|err: ErrorStack| TrustStoreError::PEMEncodingError(err))?;

//         let mut tee_cmd = Command::new("sudo")
//             .arg("tee")
//             .arg(pem_path.to_str().unwrap())
//             .stdin(Stdio::piped())
//             .stdout(Stdio::null())
//             .spawn()
//             .map_err(|err| {
//                 TrustStoreError::CommandError(format!(
//                     "{}: Failed to run sudo tee: {}",
//                     "Error".red(),
//                     err
//                 ))
//             })?;

//         tee_cmd
//             .stdin
//             .as_mut()
//             .ok_or(TrustStoreError::CommandError(
//                 "Failed to open tee stdin".to_string(),
//             ))?
//             .write_all(&cert_pem)
//             .map_err(|err: io::Error| {
//                 TrustStoreError::PEMFileCreationError(io::Error::new(io::ErrorKind::Other, err))
//             })?;

//         let status = tee_cmd.wait().map_err(|err| {
//             TrustStoreError::CommandError(format!(
//                 "{}: Failed to wait for tee: {}",
//                 "Error".red(),
//                 err
//             ))
//         })?;

//         if !status.success() {
//             return Err(TrustStoreError::CommandError(
//                 "Tee command failed".to_string(),
//             ));
//         }

//         Ok(())
//     }

//     fn update_trust_settings(&self, cert_path: &Path) -> Result<(), TrustStoreError> {
//         let mut temp_file = NamedTempFile::new().map_err(|err| {
//             TrustStoreError::CommandError(format!("Failed to create temp file: {}", err))
//         })?;

//         let status = Command::new("sudo")
//             .args(&[
//                 "security",
//                 "trust-settings-export",
//                 "-d",
//                 temp_file.path().to_str().unwrap(),
//             ])
//             .status()
//             .map_err(|err| {
//                 TrustStoreError::CommandError(format!("Failed to export trust settings: {}", err))
//             })?;

//         if !status.success() {
//             return Err(TrustStoreError::CommandError(
//                 "trust-settings-export command failed".to_string(),
//             ));
//         }

//         let mut plist_data = Vec::new();
//         temp_file.read_to_end(&mut plist_data).map_err(|err| {
//             TrustStoreError::CommandError(format!("Failed to read trust settings: {}", err))
//         })?;

//         let mut plist_root: Value = plist::from_bytes(&plist_data).map_err(|err| {
//             TrustStoreError::CommandError(format!("Failed to parse plist: {}", err))
//         })?;

//         self.modify_trust_settings(&mut plist_root, cert_path)?;

//         let updated_data = plist::to_bytes(&plist_root).map_err(|err| {
//             TrustStoreError::CommandError(format!("Failed to serialize plist: {}", err))
//         })?;
//         temp_file.write_all(&updated_data).map_err(|err| {
//             TrustStoreError::CommandError(format!(
//                 "Failed to write updated trust settings: {}",
//                 err
//             ))
//         })?;

//         let status = Command::new("sudo")
//             .args(&[
//                 "security",
//                 "trust-settings-import",
//                 "-d",
//                 temp_file.path().to_str().unwrap(),
//             ])
//             .status()
//             .map_err(|err| {
//                 TrustStoreError::CommandError(format!(
//                     "Failed to import updated trust settings: {}",
//                     err
//                 ))
//             })?;

//         if !status.success() {
//             return Err(TrustStoreError::CommandError(
//                 "trust-settings-import command failed".to_string(),
//             ));
//         }

//         Ok(())
//     }

//     fn modify_trust_settings(
//         &self,
//         plist_root: &mut Value,
//         _cert_path: &Path,
//     ) -> Result<(), TrustStoreError> {
//         let root_subject_asn1 = self.certificate_subject_asn1()?;

//         if let Some(plist_dict) = plist_root.as_dictionary_mut() {
//             // Ensure trust settings version is 1, as in the Go code
//             if let Some(Value::Integer(trust_version)) = plist_dict.get("trustVersion") {
//                 if *trust_version != 1 {
//                     return Err(TrustStoreError::CommandError(format!(
//                         "Unsupported trust settings version: {}",
//                         trust_version
//                     )));
//                 }
//             }

//             // Get the trustList entry and check for matching issuerName
//             if let Some(Value::Dictionary(trust_list)) = plist_dict.get_mut("trustList") {
//                 for (key, entry) in trust_list.iter_mut() {
//                     if let Some(entry_dict) = entry.as_dictionary_mut() {
//                         if let Some(Value::Data(issuer_name)) = entry_dict.get("issuerName") {
//                             if issuer_name == &root_subject_asn1 {
//                                 // Match found; modify the trust settings
//                                 entry_dict.insert(
//                                     "trustSettings".to_string(),
//                                     Value::Array(vec![
//                                         Value::Dictionary(HashMap::from([
//                                             (
//                                                 "kSecTrustSettingsPolicy".to_string(),
//                                                 Value::Data(vec![
//                                                     0x2a, 0x03, 0x28, 0x72, 0x36, 0x0e,
//                                                 ]),
//                                             ),
//                                             (
//                                                 "kSecTrustSettingsPolicyName".to_string(),
//                                                 Value::String("sslServer".to_string()),
//                                             ),
//                                             (
//                                                 "kSecTrustSettingsResult".to_string(),
//                                                 Value::Integer(1),
//                                             ),
//                                         ])),
//                                         Value::Dictionary(HashMap::from([
//                                             (
//                                                 "kSecTrustSettingsPolicy".to_string(),
//                                                 Value::Data(vec![
//                                                     0x2a, 0x03, 0x28, 0x72, 0x36, 0x0c,
//                                                 ]),
//                                             ),
//                                             (
//                                                 "kSecTrustSettingsPolicyName".to_string(),
//                                                 Value::String("basicX509".to_string()),
//                                             ),
//                                             (
//                                                 "kSecTrustSettingsResult".to_string(),
//                                                 Value::Integer(1),
//                                             ),
//                                         ])),
//                                     ]),
//                                 );
//                                 return Ok(()); // Trust settings modified successfully
//                             }
//                         }
//                     }
//                 }
//             }
//         }

//         Err(TrustStoreError::CommandError(
//             "Failed to find matching trust settings entry".to_string(),
//         ))
//     }

//     fn certificate_subject_asn1(&self) -> Result<Vec<u8>, TrustStoreError> {
//         let subject_name: X509Name = self.certificate.subject_name().to_owned().unwrap();
//         subject_name
//             .to_der()
//             .map_err(|err| TrustStoreError::PEMEncodingError(err.into()))
//     }
// }
