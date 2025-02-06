// SPDX-License-Identifier: BSD-3-Clause

use clap::Parser;
use clap_stdin::MaybeStdin;

#[derive(Debug, Parser)]
#[clap(name="ssg-sudo-shim", version=env!("CARGO_PKG_VERSION"),about=env!("CARGO_PKG_DESCRIPTION"), author=env!("CARGO_PKG_AUTHORS"))]
pub struct Cli {
    /// The desktop file to search for
    pub cmd: MaybeStdin<String>,

    /// save the local environment and reimport it in the ssh session
    #[clap(long, default_value_t = false)]
    pub keep_env: bool,
}
