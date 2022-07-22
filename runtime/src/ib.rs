use argon2::{
    password_hash::{
        PasswordHasher, SaltString
    },
    Argon2
};

use crate::detect_pci;

pub struct IBInfo {
    pub id: String,
}

impl IBInfo {
    pub fn try_new() -> anyhow::Result<IBInfo> {

        let infiniband_vendor_id = String::from("1077");
        let mut infiniband_id = String::from("None");

        match std::env::var("IB_PCI") {
            Ok(val) => {
                if val != "no" {
                    let infiniband_pci_id = String::from(val);
                    let infiniband_name = detect_pci::detect_pci(infiniband_pci_id, infiniband_vendor_id);

                    if infiniband_name != "None" {
                        match std::env::var("IB_CLUSTER_ID") {
                            Ok(val) => {
                                let infiniband_secret = val;
                                let argon2 = Argon2::default();
                                let string_salt = SaltString::new("GolemNetwork").unwrap();
                                let salt = string_salt.as_salt();
                                let full_hash = argon2.hash_password(infiniband_secret.as_bytes(), &salt).unwrap();
                                infiniband_id = full_hash.hash.unwrap().to_string();
                            },
                            Err(_e) => {}
                        }

                    }
                }
            },
            Err(_e) => {}
        }

        Ok(IBInfo {
            id: infiniband_id,
        })

    }
}

