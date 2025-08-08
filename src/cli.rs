use crate::security::{create_and_save_passcode_passphrase, load_passphrase_decipher};

pub fn init() {
    let passphrase_result = load_passphrase_decipher();
    if passphrase_result.is_ok() {
        eprintln!("Error: already initialized");
        std::process::exit(1);
    }
    create_and_save_passcode_passphrase().expect("create passcode & passphrase")
}

pub fn encrypt() {}
