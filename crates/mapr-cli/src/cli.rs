use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Network request flow mapping and path diagnostics CLI.
#[derive(Parser, Debug)]
#[command(
    name = "mapr",
    about = "Maps how requests flow across cloud providers, DNS, CDNs, and load balancers",
    version
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Commands,
}

/// Global flags that behave identically across all commands.
#[derive(Args, Debug, Clone)]
pub struct GlobalArgs {
    /// Output format (defaults to text on a TTY, json when piped)
    #[arg(long, global = true, value_enum)]
    pub output: Option<CliOutputFormat>,

    /// Never prompt interactively
    #[arg(long, global = true)]
    pub no_prompt: bool,

    /// No network calls beyond what is explicitly needed
    #[arg(long, global = true)]
    pub offline: bool,

    /// Mask account IDs, ARNs and IPs in output
    #[arg(long, global = true)]
    pub redact: bool,

    /// Timeout duration (e.g. 10s, 2m)
    #[arg(long, global = true)]
    pub timeout: Option<String>,

    /// Enable verbose diagnostic logs
    #[arg(long, global = true, conflicts_with = "quiet")]
    pub verbose: bool,

    /// Suppress informational messages
    #[arg(long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Save trace output to a file
    #[arg(long, global = true)]
    pub save: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliOutputFormat {
    Json,
    Text,
    Mermaid,
    Dot,
    Html,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Full path, using available credentials. Where do requests to this target go?
    Trace {
        /// Hostname, CNAME, IP or CIDR target
        target: String,
    },

    /// What points at this resource? Where do requests to this target come from?
    Reverse {
        /// Target resource ARN, ID, or name
        resource: String,
    },

    /// What changed between two traces?
    Diff {
        /// Path to first trace file
        a: PathBuf,

        /// Path to second trace file
        b: PathBuf,

        /// Return exit code 3 if changes are detected
        #[arg(long)]
        exit_code: bool,
    },

    /// Manage and inspect provider authentication
    Auth {
        #[command(subcommand)]
        action: AuthCommands,
    },

    /// Turn a saved trace into text, mermaid, dot, or html
    Render {
        /// Path to saved trace JSON file
        file: PathBuf,
    },

    /// Run as an MCP server for AI agents
    Mcp,
}

#[derive(Subcommand, Debug)]
pub enum AuthCommands {
    /// Which providers can I reach, and with what access?
    Status,

    /// Set or select authentication profile for a provider
    Set {
        /// Provider name (e.g. aws)
        provider: String,

        /// Optional profile name
        #[arg(long)]
        profile: Option<String>,
    },

    /// Remove authentication configuration for a provider
    Rm {
        /// Provider name (e.g. aws)
        provider: String,

        /// Optional profile name
        #[arg(long)]
        profile: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_parsing_trace() {
        let args = [
            "mapr",
            "--output",
            "json",
            "--offline",
            "trace",
            "example.com",
        ];
        let Ok(cli) = Cli::try_parse_from(args) else {
            panic!("Failed to parse trace command");
        };
        assert_eq!(cli.global.output, Some(CliOutputFormat::Json));
        assert!(cli.global.offline);
        match cli.command {
            Commands::Trace { target } => assert_eq!(target, "example.com"),
            _ => panic!("Expected trace command"),
        }
    }

    #[test]
    fn test_cli_parsing_auth_status() {
        let args = ["mapr", "auth", "status"];
        let Ok(cli) = Cli::try_parse_from(args) else {
            panic!("Failed to parse auth status command");
        };
        match cli.command {
            Commands::Auth { action } => match action {
                AuthCommands::Status => {}
                _ => panic!("Expected auth status command"),
            },
            _ => panic!("Expected auth command"),
        }
    }

    #[test]
    fn test_cli_parsing_diff() {
        let args = ["mapr", "diff", "trace1.json", "trace2.json", "--exit-code"];
        let Ok(cli) = Cli::try_parse_from(args) else {
            panic!("Failed to parse diff command");
        };
        match cli.command {
            Commands::Diff { a, b, exit_code } => {
                assert_eq!(a, std::path::Path::new("trace1.json"));
                assert_eq!(b, std::path::Path::new("trace2.json"));
                assert!(exit_code);
            }
            _ => panic!("Expected diff command"),
        }
    }
}
