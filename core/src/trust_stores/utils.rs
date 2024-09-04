use std::{fs, io};

pub fn check_if_firefox_exists() -> Result<bool, io::Error> {
    let firefox_paths: Vec<String> = vec![
        "/usr/bin/firefox".to_string(),
        "/usr/bin/firefox-nightly".to_string(),
        "/usr/bin/firefox-developer-edition".to_string(),
        "/snap/firefox".to_string(),
        "/Applications/Firefox.app".to_string(),
        "/Applications/FirefoxDeveloperEdition.app".to_string(),
        "/Applications/Firefox Developer Edition.app".to_string(),
        "/Applications/Firefox Nightly.app".to_string(),
        "C:\\Program Files\\Mozilla Firefox".to_string(),
    ];

    for path in firefox_paths {
        if fs::metadata(&path).is_ok() {
            return Ok(true);
        }
    }

    Ok(false)
}
