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

use crate::Host;
use clap::Parser;

pub const DEFAULT_I2P_PROXY: &str = "127.0.0.1:4447";
pub const DEFAULT_TOR_PROXY: &str = "127.0.0.1:9050";
pub const DEFAULT_QUEUE_SIZE: usize = 0x10000 / std::mem::size_of::<*const Host>(); // About 64KiB

/// Client to verify XMRIGISO server signatures using Ed25519
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Args {
    /// File containing list of hosts
    #[arg(short, long)]
    pub file: Option<Vec<String>>,

    /// I2P proxy hostname and port
    #[arg(long, default_value = DEFAULT_I2P_PROXY)]
    pub i2p_proxy: String,

    /// Tor proxy hostname and port
    #[arg(long, default_value = DEFAULT_TOR_PROXY)]
    pub tor_proxy: String,

    /// Host queue size
    #[arg(short, long, default_value_t = DEFAULT_QUEUE_SIZE)]
    pub queue_size: usize,

    /// Enable debug logging
    #[arg(short, long)]
    pub debug: bool,

    /// Enable detailed trace logging
    #[arg(short, long)]
    pub trace: bool,

    /// Print copyright information
    #[arg(short, long)]
    pub copyright: bool,

    /// Print full license text
    #[arg(long, hide = true)]
    pub license: bool,

    /// Generate shell completion script for the specified shell
    #[arg(long, value_name = "SHELL")]
    pub completion: Option<String>,

    /// Hostname with optional protocol, port, and endpoint
    pub host: Option<String>,

    /// SOCKS5 proxy hostname and port
    pub proxy: Option<String>,
}
