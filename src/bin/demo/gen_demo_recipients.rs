use anyhow::Result;
use silent_pay::demo::{generate_demo_recipients, save_demo_recipients};
use std::path::PathBuf;

fn main() -> Result<()> {
    let out_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("demo/recipients.toml"));

    let recipients = generate_demo_recipients();
    save_demo_recipients(&out_path, &recipients)?;

    println!(
        "Wrote {} demo recipient(s) to {}",
        recipients.len(),
        out_path.display()
    );
    Ok(())
}
