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
) {
    if request {
        // ONLY CSR (CA Not Required)
        for domain in &domains {}
    }

    if certfile.is_some() {
        // check file data
        // Correct
        if csr.is_some() {
            // Generate for this CSR
        }
        for domain in &domains {}

        // NOT Correct
        // Error - Files not correct
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
}
