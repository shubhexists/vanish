mod get_unique_hash {
    use crate::utils::get_unique_hash;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const CSR_DATA: &[u8; 954] = b"-----BEGIN CERTIFICATE REQUEST-----\n
MIICfTCCAWUCAQAwETEPMA0GA1UECgwGVmFuaXNoMIIBIjANBgkqhkiG9w0BAQEF\n
AAOCAQ8AMIIBCgKCAQEAu6yXUMzVfqCBGOJh50MziGFKShMWQt7iIYe2pAeFBoeo\n
uuwuVq4xSdqpgTFvkhekH8tpTX8n+Y8pY7rur6Nosi/G2A6AxvvwG/ahDuHYg9Il\n
XmTYrqKnK32n/8ALPT6W3J6wKq6Nm2y5yXhGX/fSVSrmNw78hl0osKLUa7dLmCs0\n
zBghTfwjSz+qkUXvwEKuGPqgXLh6hirjiNhbtbR1XgV3p/w/7u3qH7fJcDlrhQDW\n
QhJnxcdYGCMGGcIzEdGaNzTHNAlpU7lLR2FTEjk7OCYwDgzLFYy6QFdeK2swdkfn\n
OlipnXQfzFUEbTKDQUckLafodJBzLhqyKCulDPxqoQIDAQABoCcwJQYJKoZIhvcN\n
AQkOMRgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEB\n
ACwI/gFmKb5oAahbq2LlnkGtAwmbV67xgxTmXXUIvJs37cz4Rde/CdSDct5g7mYh\n
8EghzWLEfHmg9K9kMiV58HHYIkcQ421v+pPub3wDVU3yvq3/DpIqHDBs/Wz3nFrI\n
GZEfI1cwUTqTkK9Lk2z3waUkt8adk4pvof01tiEq9A06GjK5tJfUIGef4lkOfzKE\n
ld7i9gqfMk+9pmSjBYVG0YCfc0ye/oPhmSNtFc9dTlBb9bqcN3C0dgqdhM3E/4Gz\n
YBni+0GjtUKZT9NsekFh/O14P6j9MrtbHsMLWU6KXgHc+t75kD+XKy2U/IPd8nzt\n
ncq6d7m7pfbZs5a+gBnsPqA=\n
-----END CERTIFICATE REQUEST-----";

    #[test]
    fn returns_ok() {
        let mut temp_file: NamedTempFile = NamedTempFile::new().unwrap();
        temp_file.write_all(CSR_DATA).unwrap();
        let csr_path: &str = temp_file.path().to_str().unwrap();

        let hash_result: Result<String, std::io::Error> = get_unique_hash(csr_path);
        assert!(hash_result.is_ok(), "Expected Ok result, got an error");
    }

    #[test]
    fn hash_length() {
        let mut temp_file: NamedTempFile = NamedTempFile::new().unwrap();
        temp_file.write_all(CSR_DATA).unwrap();
        let csr_path: &str = temp_file.path().to_str().unwrap();

        let unique_hash: String = get_unique_hash(csr_path).unwrap();
        assert_eq!(unique_hash.len(), 43, "Expected hash length of 43");
    }

    #[test]
    fn consistent() {
        let mut temp_file: NamedTempFile = NamedTempFile::new().unwrap();
        temp_file.write_all(CSR_DATA).unwrap();
        let csr_path: &str = temp_file.path().to_str().unwrap();

        let hash1: String = get_unique_hash(csr_path).unwrap();
        let hash2: String = get_unique_hash(csr_path).unwrap();
        assert_eq!(hash1, hash2, "Hashes for the same file should be equal");
    }
}

mod serial_number {
    use crate::utils::generate_certificate_serial_number;

    #[test]
    fn returns_ok() {
        let result: Result<openssl::asn1::Asn1Integer, crate::errors::SerialNumberError> =
            generate_certificate_serial_number();
        assert!(result.is_ok(), "Expected Ok result");
    }

    #[test]
    fn is_valid() {
        let result: Result<openssl::asn1::Asn1Integer, crate::errors::SerialNumberError> =
            generate_certificate_serial_number();
        let asn1_integer: openssl::asn1::Asn1Integer = result.unwrap();
        let serial_bytes: Vec<u8> = asn1_integer.to_bn().unwrap().to_vec();
        assert!(!serial_bytes.is_empty(), "ASN1 Integer should not be empty");

        let is_negative: bool = asn1_integer.to_bn().unwrap().is_negative();
        assert!(!is_negative, "ASN1 Integer should not be negative");

        assert!(
            serial_bytes.len() <= 16,
            "ASN1 Integer should fit within 128 bits (16 bytes)"
        );
    }
}
