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
use log::{error, info, LevelFilter};
use std::fs::File;
use std::io::{BufRead, BufReader};
mod host;

use host::Host;
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
            process_files(files).await
        } else if let Some(host) = args.host {
            process_host(&host, args.socks5_proxy.as_deref()).await
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

async fn process_files(files: Vec<String>) -> Result<String, String> {
    for file in files {
        let file = File::open(file).map_err(|_| "Failed to open file")?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line.map_err(|_| "Failed to read line")?;
            if let Some((host, proxy)) = parse_line(&line) {
                let mut host = Host::new(&host, proxy.as_deref());
                if host.check().await.is_ok() {
                    return Ok(host.url);
                }
            }
        }
    }
    Err("No valid host found".to_string())
}

async fn process_host(host: &str, proxy: Option<&str>) -> Result<String, String> {
    let mut host = Host::new(host, proxy);
    host.check().await?;
    Ok(host.url)
}

fn parse_line(line: &str) -> Option<(String, Option<String>)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.len() {
        1 => Some((parts[0].to_string(), None)),
        2 => Some((parts[0].to_string(), Some(parts[1].to_string()))),
        _ => None,
    }
}
