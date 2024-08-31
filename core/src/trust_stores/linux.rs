pub struct CAValue {}

impl CAValue {}

enum PossibleStores {
    RedHat,
    Debian,
    SuSE,
    Other,
}

impl PossibleStores {
    fn get_details(&self) -> (String, Vec<&'static str>) {
        match self {
            PossibleStores::RedHat => (
                "/etc/pki/ca-trust/source/anchors/".to_string(),
                vec!["update-ca-trust", "extract"],
            ),
            PossibleStores::Debian => (
                "/usr/local/share/ca-certificates/".to_string(),
                vec!["update-ca-certificates"],
            ),
            PossibleStores::SuSE => (
                "/etc/ca-certificates/trust-source/anchors/".to_string(),
                vec!["trust", "extract-compat"],
            ),
            PossibleStores::Other => (
                "/usr/share/pki/trust/anchors/".to_string(),
                vec!["update-ca-certificates"],
            ),
        }
    }
}
