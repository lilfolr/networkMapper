#![forbid(unsafe_code)]

mod cli;
mod commands;

use clap::Parser;
use cli::{Cli, Commands};
use mapr_schema::ExitCode;

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Trace { target } => commands::trace::run(target, &cli.global),
        Commands::Reverse { resource } => commands::reverse::run(resource, &cli.global),
        Commands::Diff { a, b, exit_code } => commands::diff::run(a, b, *exit_code, &cli.global),
        Commands::Auth { action } => commands::auth::run(action, &cli.global),
        Commands::Render { file } => commands::render::run(file, &cli.global),
        Commands::Mcp => commands::mcp::run(&cli.global),
    };

    match result {
        Ok(code) => code.into(),
        Err(err) => {
            eprintln!("Error: {err:?}");
            ExitCode::Error.into()
        }
    }
}
