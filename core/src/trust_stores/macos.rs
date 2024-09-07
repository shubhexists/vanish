use openssl::error;
use openssl::x509::X509;
use plist::{from_bytes, to_writer_xml, Value};
use std::fs::{self, File};
use std::io::{self, Read};
use std::process::Command;

pub struct CAValue {
    ca_cert: X509,
    ca_root: String,
}

impl CAValue {
    pub fn install_platform(&self) -> Result<bool, String> {
        let cert_path = format!("{}/{}", self.ca_root, "rootCA.pem");
        let output = Command::new("sudo")
            .arg("security")
            .arg("add-trusted-cert")
            .arg("-d")
            .arg("-k")
            .arg("/Library/Keychains/System.keychain")
            .arg(&cert_path)
            .output()
            .map_err(|e| format!("Failed to execute security add-trusted-cert: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Error executing security add-trusted-cert: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let temp_file_path: &str = "/tmp/trust-settings.plist";
        let mut temp_file: File = File::create(temp_file_path)
            .map_err(|e: io::Error| format!("Failed to create temp file: {}", e))?;

        let output = Command::new("sudo")
            .arg("security")
            .arg("trust-settings-export")
            .arg("-d")
            .arg(temp_file_path)
            .output()
            .map_err(|e: io::Error| {
                format!("Failed to execute security trust-settings-export: {}", e)
            })?;

        if !output.status.success() {
            return Err(format!(
                "Error executing security trust-settings-export: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let mut plist_data: Vec<u8> = Vec::new();
        temp_file
            .read_to_end(&mut plist_data)
            .map_err(|e: io::Error| format!("Failed to read trust settings: {}", e))?;

        let mut plist_root: Value = from_bytes(&plist_data)
            .map_err(|e: plist::Error| format!("Failed to parse trust settings plist: {}", e))?;

        let root_subject_asn1: Vec<u8> = self
            .ca_cert
            .subject_name()
            .to_der()
            .map_err(|e: error::ErrorStack| format!("Failed to marshal CA subject: {}", e))?;

        if plist_root.as_dictionary().unwrap()["trustVersion"]
            .as_unsigned_integer()
            .unwrap()
            != 1
        {
            return Err("ERROR: unsupported trust settings version".to_string());
        }

        let trust_list = plist_root
            .as_dictionary_mut()
            .unwrap()
            .get_mut("trustList")
            .unwrap()
            .as_dictionary_mut()
            .unwrap();

        for (_key, entry_value) in trust_list.iter_mut() {
            let entry = entry_value.as_dictionary_mut().unwrap();
            if let Some(issuer_name) = entry.get("issuerName") {
                if issuer_name.as_data().unwrap() == &root_subject_asn1 {
                    entry.insert(
                        "trustSettings".to_string(),
                        Value::Array(vec![
                            Value::Dictionary({
                                let mut dict = plist::Dictionary::new();
                                dict.insert(
                                    "kSecTrustSettingsPolicy".to_string(),
                                    Value::Data(vec![
                                        0x28, 0xA3, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x01,
                                    ]),
                                );
                                dict.insert(
                                    "kSecTrustSettingsPolicyName".to_string(),
                                    Value::String("sslServer".to_string()),
                                );
                                dict.insert(
                                    "kSecTrustSettingsResult".to_string(),
                                    Value::Integer(1_i64.into()),
                                );
                                dict
                            }),
                            Value::Dictionary({
                                let mut dict = plist::Dictionary::new();
                                dict.insert(
                                    "kSecTrustSettingsPolicy".to_string(),
                                    Value::Data(vec![
                                        0x28, 0xA3, 0x48, 0x86, 0xF7, 0x63, 0x64, 0x02,
                                    ]),
                                );
                                dict.insert(
                                    "kSecTrustSettingsPolicyName".to_string(),
                                    Value::String("basicX509".to_string()),
                                );
                                dict.insert(
                                    "kSecTrustSettingsResult".to_string(),
                                    Value::Integer(1.into()),
                                );
                                dict
                            }),
                        ]),
                    );
                    break;
                }
            }
        }

        let mut temp_file = File::create(temp_file_path)
            .map_err(|e| format!("Failed to write trust settings: {}", e))?;
        to_writer_xml(&mut temp_file, &plist_root)
            .map_err(|e| format!("Failed to serialize trust settings: {}", e))?;

        let output = Command::new("sudo")
            .arg("security")
            .arg("trust-settings-import")
            .arg("-d")
            .arg(temp_file_path)
            .output()
            .map_err(|e| format!("Failed to execute security trust-settings-import: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Error executing security trust-settings-import: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        fs::remove_file(temp_file_path).ok();

        Ok(true)
    }

    pub fn uninstall_platform(&self) -> Result<bool, String> {
        let cert_path = format!("{}/{}", self.ca_root, "rootCA.pem");
        let output = Command::new("sudo")
            .arg("security")
            .arg("remove-trusted-cert")
            .arg("-d")
            .arg(&cert_path)
            .output()
            .map_err(|e| format!("Failed to execute security remove-trusted-cert: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Error executing security remove-trusted-cert: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        Ok(true)
    }
}
