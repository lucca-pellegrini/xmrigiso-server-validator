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

use crate::args::ARGS;
use curl::easy::Easy;
use log::{debug, info, trace, warn};
use openssl::rand::rand_bytes;
use openssl::sign::Verifier;
use openssl::{base64, pkey::PKey};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Host {
    pub url: String,
    pub proxy: Option<String>,
    pub checked: bool,
    pub result: Option<String>,
    pub last_checked: Option<u64>,
}

impl Host {
    pub fn new(host: &str, proxy: Option<&str>) -> Self {
        trace!("Creating new Host with host: {}, proxy: {:?}", host, proxy);
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
            debug!(
                "Default TOR proxy {} chosen for domain {}",
                ARGS.tor_proxy, url
            );
            Some(ARGS.tor_proxy.to_string())
        } else if host.ends_with(".i2p") {
            debug!(
                "Default I2P proxy {} chosen for domain {}",
                ARGS.i2p_proxy, url
            );
            Some(ARGS.i2p_proxy.to_string())
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
        info!("Starting check for host: {}", self.url);
        let mut easy = Easy::new();
        trace!("Initialized curl Easy object");
        easy.url(&self.url).unwrap();
        easy.follow_location(false).unwrap();
        easy.accept_encoding("identity").unwrap();

        if let Some(proxy) = &self.proxy {
            easy.proxy(proxy).unwrap();
            trace!("Setting proxy: {}", proxy);
            easy.proxy_type(curl::easy::ProxyType::Socks5Hostname)
                .unwrap();
        }

        let mut random_data = vec![0u8; ARGS.data_size];
        rand_bytes(&mut random_data).unwrap();
        debug!(
            "Generated random bytes: {:?}",
            base64::encode_block(&random_data)
        );

        let response_data = match self.perform_request(&mut easy, &random_data) {
            Ok(data) => data,
            Err(err) => {
                warn!("Failed to perform request for host {}: {}", self.url, err);
                return Err("Failed to perform request".to_string());
            }
        };

        match easy.response_code() {
            Ok(code) => self.validate_response_code(code)?,
            Err(err) => return Err(format!("Failed to get response code: {}", err)),
        }

        // Check if the response data has the correct size for the signature
        if response_data.len() != ARGS.sig_size {
            return Err(format!(
                "Invalid signature size: expected {}, got {}",
                ARGS.sig_size,
                response_data.len()
            ));
        }

        debug!(
            "Received response data: {:?}",
            base64::encode_block(&response_data)
        );

        trace!("Verifying response");
        let public_key = &ARGS.key;
        let pkey = PKey::public_key_from_pem(public_key.as_bytes()).unwrap();
        let mut verifier = Verifier::new_without_digest(&pkey).unwrap();

        if let Ok(true) = verifier.verify_oneshot(&random_data, &response_data) {
            self.checked = true;
            self.result = Some(self.url.clone());
            self.last_checked = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
            info!("Verification successful for host: {}", self.url);
            Ok(())
        } else {
            warn!("Signature invalid for host: {}", self.url);
            Err("Signature invalid".to_string())
        }
    }

    fn perform_request(&self, easy: &mut Easy, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut response_data = Vec::new();
        {
            easy.post(true).unwrap();
            easy.post_field_size(data.len() as u64).unwrap();

            let mut transfer = easy.transfer();
            transfer
                .read_function(|buf| {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    Ok(len)
                })
                .unwrap();

            transfer
                .write_function(|data| {
                    response_data.extend_from_slice(data);
                    Ok(data.len())
                })
                .unwrap();

            trace!("Performing POST request to {}", self.url);
            if let Err(err) = transfer.perform() {
                return Err(err.to_string());
            }
        } // End of transfer scope
        Ok(response_data)
    }

    fn validate_response_code(&self, response_code: u32) -> Result<(), String> {
        trace!("Received response code: {}", response_code);
        match response_code {
            300..=399 => {
                return Err(format!(
                    "Request was redirected with response code: {}",
                    response_code
                ));
            }
            400..=599 => {
                return Err(format!("Request returned error code: {}", response_code));
            }
            _ => {
                debug!("Request successful with response code: {}", response_code);
            }
        }
        Ok(())
    }
}
