mod cache;
mod cli;
mod config;
mod crypto;
mod error;
mod providers;
mod shell;
mod sync;

use colored::Colorize;

#[tokio::main]
async fn main() {
    match cli::run().await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("{} {}", "✖ error:".red().bold(), e);
            std::process::exit(1);
        }
    }
}
