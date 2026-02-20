use anyhow::Result;
use clap::Parser;
use soroban_debugger::cli::{Cli, Commands};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "soroban_debugger=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse CLI arguments
    let cli = Cli::parse();

    // Handle verbose version
    if cli.version_verbose {
        println!("Soroban Debugger {}", env!("CARGO_PKG_VERSION"));
        println!("Soroban SDK: {}", "22.0.0"); // Hardcoded for now, or could be extracted
        println!("Rust Version: {}", env!("RUSTC_VERSION"));
        println!("Git Commit: {}", env!("GIT_HASH"));
        
        // Convert build date from timestamp
        let build_date = env!("BUILD_DATE");
        if let Ok(secs) = build_date.parse::<u64>() {
            use std::time::{Duration, UNIX_EPOCH};
            let d = UNIX_EPOCH + Duration::from_secs(secs);
            println!("Build Date: {:?}", d);
        } else {
            println!("Build Date: unknown");
        }
        return Ok(());
    }

    // Execute command
    match cli.command {
        Some(Commands::Run(args)) => {
            soroban_debugger::cli::commands::run(args)?;
        }
        Some(Commands::Interactive(args)) => {
            soroban_debugger::cli::commands::interactive(args)?;
        }
        Some(Commands::Inspect(args)) => {
            soroban_debugger::cli::commands::inspect(args)?;
        }
        None => {
            println!("No command specified. Use --help for usage.");
        }
    }

    Ok(())
}