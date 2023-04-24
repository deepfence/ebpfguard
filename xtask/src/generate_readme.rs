use std::{env::current_dir, fs::File};

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    /// Do not overwrite the README.md file, just check whether it is up to date.
    #[clap(long, default_value_t = false)]
    check: bool,
}

pub fn generate_readme(opts: Options) -> anyhow::Result<()> {
    let project_root = current_dir()?.join("ebpfguard");
    let mut source = File::open("ebpfguard/src/lib.rs")?;
    let mut template = File::open("README.tpl")?;

    let content = cargo_readme::generate_readme(
        project_root.as_path(),
        &mut source,
        Some(&mut template),
        true,
        true,
        true,
        true,
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    if opts.check {
        let readme = std::fs::read_to_string("README.md")?;
        if readme != content {
            anyhow::bail!("README.md is not up to date");
        }
    } else {
        std::fs::write("README.md", content)?;
    }

    Ok(())
}
