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

use crate::args::ARGS;
use args::Args;
use clap::CommandFactory;
use clap_complete::{generate, Shell};
use host::Host;
use license::License;
use log::{debug, error, info, trace, LevelFilter};
use std::fs::File;
use std::io::{BufRead, BufReader};
use tokio::{runtime::Runtime, sync::mpsc, task};

fn main() {
    debug!("Parsed arguments: {:?}", ARGS);

    if let Some(shell) = &ARGS.completion {
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
            env!("CARGO_PKG_NAME"),
            &mut std::io::stdout(),
        );
        return;
    }

    let license: &dyn License = env!("CARGO_PKG_LICENSE").parse().unwrap();

    if ARGS.copyright {
        println!(
            "{} ({}) — {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_DESCRIPTION")
        );
        println!(
            "{}",
            license.header().unwrap().replace(
                "[yyyy] [name of copyright owner]",
                env!("CARGO_PKG_AUTHORS")
            )
        );
        std::process::exit(0);
    }

    if ARGS.license {
        println!("{}", license.text());
        std::process::exit(0);
    }

    if ARGS.trace {
        env_logger::Builder::new()
            .filter(None, LevelFilter::Trace)
            .init();
    } else if ARGS.debug {
        env_logger::Builder::new()
            .filter(None, LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::new()
            .filter(None, LevelFilter::Info)
            .init();
    }

    let rt = Runtime::new().unwrap();
    trace!("Created Tokio runtime");
    let result = rt.block_on(async {
        if let Some(files) = &ARGS.file {
            process_files(files.to_vec(), ARGS.queue_size).await
        } else if let Some(host) = &ARGS.host {
            process_host(&host, ARGS.proxy.as_deref()).await
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
            trace!("Consuming host: {}, proxy: {:?}", host, proxy);
            let mut host = Host::new(&host, proxy.as_deref());
            if host.check().await.is_ok() {
                return Ok(host.url);
            }
        }
        Err("No valid host found".to_string())
    });

    // Producer logic: parse lines and send to the queue
    for filename in files {
        trace!("Opening file: {}", filename);
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
                trace!("Parsed line into host: {}, proxy: {:?}", host, proxy);
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
    trace!("Processing host: {}, with proxy: {:?}", host, proxy);
    let mut host = Host::new(host, proxy);
    host.check().await?;
    Ok(host.url)
}

fn parse_line(line: &str) -> Option<(String, Option<String>)> {
    trace!("Parsing line: {}", line);
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.len() {
        1 => Some((parts[0].to_string(), None)),
        2 => Some((parts[0].to_string(), Some(parts[1].to_string()))),
        _ => None,
    }
}
