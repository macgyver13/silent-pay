use anyhow::{Context, Result};
use psbt::Psbt;

pub fn read(path: impl AsRef<std::path::Path>) -> Result<Psbt> {
    Psbt::deserialize(&std::fs::read(path)?).context("deserialize PSBT")
}

pub fn write(psbt: &Psbt, path: impl AsRef<std::path::Path>) -> Result<()> {
    std::fs::write(path, psbt.serialize()).context("write PSBT")
}
