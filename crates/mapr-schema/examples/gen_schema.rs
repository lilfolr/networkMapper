//! Generate `schema/mapr-trace.schema.json` from the Rust types.
//!
//! Run with: `cargo run -p mapr-schema --example gen_schema`

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let schema = mapr_schema::generate_schema();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../schema/mapr-trace.schema.json"
    );
    std::fs::write(path, &schema)?;
    println!("Written: {path}");
    Ok(())
}
