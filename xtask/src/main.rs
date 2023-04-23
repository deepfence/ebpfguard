mod build_ebpf;
mod generate_readme;
mod run;

use std::process::exit;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildEbpf(build_ebpf::Options),
    GenerateReadme(generate_readme::Options),
    Run(run::Options),
}

fn main() {
    let opts = Options::parse();

    let ret = match opts.command {
        Command::BuildEbpf(opts) => build_ebpf::build_ebpf(opts),
        Command::GenerateReadme(opts) => generate_readme::generate_readme(opts),
        Command::Run(opts) => run::run(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
