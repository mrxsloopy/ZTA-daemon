#![warn(clippy::pedantic)]
mod config;
use clap::Parser;
use std::path::PathBuf;
use crate::config::load_policy;

#[derive(Parser, Debug)]
#[command(name = "ZTA PDP daemon")]
#[command(version = "1.0")]
#[command(about = "Zero trust", long_about = None)]
struct Args {
    /// Path to the TOML file with access policies
    #[arg(short, long, value_name = "daemon.toml")]
    config: PathBuf,  // no Option<>

    /// The address and port on which the daemon will run
    #[arg(short, long, value_name = "127.0.0.1:8080")]
    bind: Option<String>,
}
fn main() {
    let args = Args::parse();
    // NOTE: clap treats non-Option fields as required arguments
    // If '--config' is missing, clap exits before main() runs (prints usage + error)

    /*let config_path = match &args.config {
        Some(path) => path,
        None => {
            eprintln!("config is required");
            std::process::exit(1);
        } 
    };*/

    let policy = match load_policy(&args.config) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("config error: {e}");
            std::process::exit(1);
        },
    };
    println!("policy loaded: {policy:?}");
}
