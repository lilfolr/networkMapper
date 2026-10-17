use anyhow::Result;
use mapr_schema::ExitCode;
use std::path::Path;

use crate::cli::GlobalArgs;

pub fn run(a: &Path, b: &Path, exit_code_flag: bool, global: &GlobalArgs) -> Result<ExitCode> {
    if !global.quiet {
        eprintln!(
            "Comparing traces between '{}' and '{}' (deferred/placeholder)",
            a.display(),
            b.display()
        );
    }

    println!(
        "No differences found between '{}' and '{}' (placeholder).",
        a.display(),
        b.display()
    );

    let has_changes = false;
    if has_changes && exit_code_flag {
        Ok(ExitCode::DiffChanges)
    } else {
        Ok(ExitCode::Success)
    }
}
