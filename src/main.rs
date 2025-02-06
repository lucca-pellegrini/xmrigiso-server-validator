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

use clap::Parser;
use curl::easy::Easy;
use log::{error, info, LevelFilter};
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use std::fs::File;
use std::io::{BufRead, BufReader};
use tokio::runtime::Runtime;

/// Client to verify server signatures using Ed25519
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Enable debug logging
    #[arg(short, long)]
    verbose: bool,

    /// I2P proxy hostname and port
    #[arg(long, default_value = "localhost:4447")]
    i2p_proxy: String,

    /// Tor proxy hostname and port
    #[arg(long, default_value = "localhost:9050")]
    tor_proxy: String,

    /// File containing list of hosts
    #[arg(short, long)]
    file: Option<Vec<String>>,

    /// Hostname with optional protocol, port, and endpoint
    host: Option<String>,

    /// SOCKS5 proxy hostname and port
    socks5_proxy: Option<String>,
}

fn main() {
    let args = Args::parse();

    if args.verbose {
        env_logger::Builder::new()
            .filter(None, LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::new()
            .filter(None, LevelFilter::Info)
            .init();
    }

    let rt = Runtime::new().unwrap();
    let result = rt.block_on(async {
        if let Some(files) = args.file {
            process_files(files, &args.i2p_proxy, &args.tor_proxy).await
        } else if let Some(host) = args.host {
            process_host(
                &host,
                args.socks5_proxy.as_deref(),
                &args.i2p_proxy,
                &args.tor_proxy,
            )
            .await
        } else {
            Err("No host or file provided. Use --help for more information.".to_string())
        }
    });

    match result {
        Ok(host) => {
            info!("Successfully verified host: {}", host);
            std::process::exit(0);
        }
        Err(err) => {
            error!("Error: {}", err);
            std::process::exit(1);
        }
    }
}

async fn process_files(
    files: Vec<String>,
    i2p_proxy: &str,
    tor_proxy: &str,
) -> Result<String, String> {
    for file in files {
        if let Ok(file) = File::open(file) {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    if let Some((host, proxy)) = parse_line(&line) {
                        if let Some(result) =
                            check_host(&host, proxy.as_deref(), i2p_proxy, tor_proxy).await
                        {
                            return Ok(result);
                        }
                    }
                }
            }
        }
    }
    Err("No valid host found".to_string())
}

async fn process_host(
    host: &str,
    proxy: Option<&str>,
    i2p_proxy: &str,
    tor_proxy: &str,
) -> Result<String, String> {
    check_host(host, proxy, i2p_proxy, tor_proxy)
        .await
        .ok_or("Failed to verify host".to_string())
}

async fn check_host(
    host: &str,
    proxy: Option<&str>,
    i2p_proxy: &str,
    tor_proxy: &str,
) -> Option<String> {
    let url = if host.starts_with("http://") || host.starts_with("https://") {
        host.to_string()
    } else if host.ends_with(".onion") || host.ends_with(".i2p") {
        host.to_string()
    } else {
        format!("https://{}", host)
    };

    let socks_proxy = if host.ends_with(".onion") {
        Some(tor_proxy)
    } else if host.ends_with(".i2p") {
        Some(i2p_proxy)
    } else {
        proxy
    };

    let mut easy = Easy::new();
    easy.url(&url).unwrap();
    easy.follow_location(true).unwrap();
    easy.accept_encoding("identity").unwrap();

    if let Some(proxy) = socks_proxy {
        easy.proxy(proxy).unwrap();
        easy.proxy_type(curl::easy::ProxyType::Socks5Hostname)
            .unwrap();
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
        if let Err(err) = transfer.perform() {
            error!("Failed to perform request to {}: {}", url, err);
            return None;
        }
    }

    let public_key = include_str!("../public_key.pem");
    let pkey = PKey::public_key_from_pem(public_key.as_bytes()).unwrap();
    let mut verifier = Verifier::new_without_digest(&pkey).unwrap();

    if verifier
        .verify_oneshot(&response_data, &response_data)
        .unwrap()
    {
        Some(url)
    } else {
        None
    }
}

fn parse_line(line: &str) -> Option<(String, Option<String>)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.len() {
        1 => Some((parts[0].to_string(), None)),
        2 => Some((parts[0].to_string(), Some(parts[1].to_string()))),
        _ => None,
    }
}
