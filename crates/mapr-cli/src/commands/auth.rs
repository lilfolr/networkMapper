use anyhow::Result;
use mapr_core::auth::check_provider_status;
use mapr_schema::ExitCode;

use crate::cli::{AuthCommands, GlobalArgs};

pub fn run(action: &AuthCommands, global: &GlobalArgs) -> Result<ExitCode> {
    match action {
        AuthCommands::Status => {
            let statuses = check_provider_status();
            if !global.quiet {
                eprintln!("Provider authentication status:");
            }
            for status in statuses {
                let reachable = if status.reachable {
                    "reachable"
                } else {
                    "unreachable"
                };
                let profile = status.profile.as_deref().unwrap_or("default");
                println!(
                    "Provider: {}\n  Profile: {}\n  Status: {}\n  Details: {}\n",
                    status.provider, profile, reachable, status.details
                );
            }
        }
        AuthCommands::Set { provider, profile } => {
            let prof = profile.as_deref().unwrap_or("default");
            if !global.quiet {
                eprintln!("Configuring auth profile for provider '{provider}' using profile '{prof}' (placeholder)");
            }
            println!("Provider '{provider}' profile set to '{prof}' (placeholder).");
        }
        AuthCommands::Rm { provider, profile } => {
            let prof = profile.as_deref().unwrap_or("all profiles");
            if !global.quiet {
                eprintln!("Removing auth profile for provider '{provider}' ({prof}) (placeholder)");
            }
            println!("Provider '{provider}' auth profile removed ({prof}) (placeholder).");
        }
    }

    Ok(ExitCode::Success)
}
