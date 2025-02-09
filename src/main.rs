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

mod args;
mod host;

use args::Args;
use clap::{CommandFactory, Parser};
use clap_complete::{generate, Shell};
use host::Host;
use log::{debug, error, info, LevelFilter};
use std::fs::File;
use std::io::{BufRead, BufReader};
use tokio::{runtime::Runtime, sync::mpsc, task};

fn main() {
    let args = Args::parse();
    debug!("Parsed arguments: {:?}", args);

    if let Some(shell) = args.completion {
        let mut app = Args::command();
        let shell = match shell.as_str() {
            "bash" => Shell::Bash,
            "zsh" => Shell::Zsh,
            "fish" => Shell::Fish,
            "powershell" => Shell::PowerShell,
            "elvish" => Shell::Elvish,
            _ => {
                eprintln!("Unsupported shell: {}", shell);
                std::process::exit(1);
            }
        };
        generate(
            shell,
            &mut app,
            "xmrigiso-server-validator",
            &mut std::io::stdout(),
        );
        return;
    }

    if args.copyright {
        println!("xmrigiso-server-validator — Verify server signatures using Ed25519");
        println!("Version: {}", env!("CARGO_PKG_VERSION"));
        println!(include_str!("misc/LICENSE-boilerplate"));
        std::process::exit(0);
    }

    if args.license {
        println!(include_str!("../LICENSE"));
        std::process::exit(0);
    }

    if args.debug {
        env_logger::Builder::new()
            .filter(None, LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::new()
            .filter(None, LevelFilter::Info)
            .init();
    }

    let rt = Runtime::new().unwrap();
    debug!("Created Tokio runtime");
    let result = rt.block_on(async {
        if let Some(files) = args.file {
            process_files(files, args.queue_size).await
        } else if let Some(host) = args.host {
            process_host(&host, args.proxy.as_deref()).await
        } else {
            let err_msg = "No host or file provided. Use --help for more information.".to_string();
            debug!("{}", err_msg);
            Err(err_msg)
        }
    });

    match result {
        Ok(host) => {
            info!("Successfully verified host: {}", host);
            std::process::exit(0);
        }
        Err(err) => {
            error!("{}", err);
            std::process::exit(1);
        }
    }
}

async fn process_files(files: Vec<String>, queue_size: usize) -> Result<String, String> {
    debug!("Processing files: {:?}", files);

    // Create a channel with a configurable buffer size
    let (tx, mut rx) = mpsc::channel::<(String, Option<String>)>(queue_size);
    debug!("Created channel for {} hosts", queue_size);

    // Spawn a consumer task
    let consumer_handle = task::spawn(async move {
        while let Some((host, proxy)) = rx.recv().await {
            debug!("Consuming host: {}, proxy: {:?}", host, proxy);
            let mut host = Host::new(&host, proxy.as_deref());
            if host.check().await.is_ok() {
                return Ok(host.url);
            }
        }
        Err("No valid host found".to_string())
    });

    // Producer logic: parse lines and send to the queue
    for filename in files {
        debug!("Opening file: {}", filename);
        let file = File::open(&filename).map_err(|err| {
            error!("Failed to open file: {}", filename);
            err.to_string()
        })?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line.map_err(|err| {
                error!("Failed to read line in file: {}", filename);
                err.to_string()
            })?;
            if let Some((host, proxy)) = parse_line(&line) {
                debug!("Parsed line into host: {}, proxy: {:?}", host, proxy);
                // Send the parsed host to the queue
                if tx.send((host, proxy)).await.is_err() {
                    error!("Failed to send host to queue");
                }
            }
        }
    }

    // Explicitly drop the sender to close the channel
    drop(tx);

    // Wait for the consumer task to complete
    debug!("Dropped sender, awaiting consumer task");
    consumer_handle.await.unwrap()
}

async fn process_host(host: &str, proxy: Option<&str>) -> Result<String, String> {
    debug!("Processing host: {}, with proxy: {:?}", host, proxy);
    let mut host = Host::new(host, proxy);
    host.check().await?;
    Ok(host.url)
}

fn parse_line(line: &str) -> Option<(String, Option<String>)> {
    debug!("Parsing line: {}", line);
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.len() {
        1 => Some((parts[0].to_string(), None)),
        2 => Some((parts[0].to_string(), Some(parts[1].to_string()))),
        _ => None,
    }
}
