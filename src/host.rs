// SPDX-License-Identifier: Apache-2.0

/*
 * xmrigiso-server-validator — Verify server signatures using Ed25519
 * Copyright 2025 Lucca Pellegrini <lucca@verticordia.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::time::{SystemTime, UNIX_EPOCH};

use curl::easy::Easy;
use log::{debug, error};
use openssl::pkey::PKey;
use openssl::sign::Verifier;

use crate::args::{DEFAULT_I2P_PROXY, DEFAULT_TOR_PROXY};

pub struct Host {
    pub url: String,
    pub proxy: Option<String>,
    pub checked: bool,
    pub result: Option<String>,
    pub last_checked: Option<u64>,
}

impl Host {
    pub fn new(host: &str, proxy: Option<&str>) -> Self {
        debug!("Creating new Host with host: {}, proxy: {:?}", host, proxy);
        let url = if host.starts_with("http://")
            || host.starts_with("https://")
            || host.ends_with(".onion")
            || host.ends_with(".i2p")
        {
            host.to_string()
        } else {
            format!("https://{}", host)
        };

        let proxy = if let Some(p) = proxy {
            Some(p.to_string())
        } else if host.ends_with(".onion") {
            Some(DEFAULT_TOR_PROXY.to_string())
        } else if host.ends_with(".i2p") {
            Some(DEFAULT_I2P_PROXY.to_string())
        } else {
            None
        };

        Host {
            url,
            proxy,
            checked: false,
            result: None,
            last_checked: None,
        }
    }

    pub async fn check(&mut self) -> Result<(), String> {
        debug!("Starting check for host: {}", self.url);
        let mut easy = Easy::new();
        debug!("Initialized curl Easy object");
        easy.url(&self.url).unwrap();
        easy.follow_location(true).unwrap();
        easy.accept_encoding("identity").unwrap();

        if let Some(proxy) = &self.proxy {
            easy.proxy(proxy).unwrap();
            debug!("Setting proxy: {}", proxy);
            easy.proxy_type(curl::easy::ProxyType::Socks5Hostname).unwrap();
        }

        let mut response_data = Vec::new();
        {
            let mut transfer = easy.transfer();
            transfer
                .write_function(|data| {
                    response_data.extend_from_slice(data);
                    Ok(data.len())
                })
                .unwrap();
            debug!("Performing request to {}", self.url);
            if let Err(err) = transfer.perform() {
                debug!("Request failed: {}", err);
                error!("Failed to perform request to {}: {}", self.url, err);
                return Err("Failed to verify host".to_string());
            }
        }

        debug!("Request successful, verifying response");
        let public_key = include_str!("../public_key.pem");
        let pkey = PKey::public_key_from_pem(public_key.as_bytes()).unwrap();
        let mut verifier = Verifier::new_without_digest(&pkey).unwrap();

        if verifier
            .verify_oneshot(&response_data, &response_data)
            .unwrap()
        {
            self.checked = true;
            self.result = Some(self.url.clone());
            self.last_checked = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
            debug!("Verification successful for host: {}", self.url);
            Ok(())
        } else {
            debug!("Verification failed for host: {}", self.url);
            Err("Failed to verify host".to_string())
        }
    }
}
