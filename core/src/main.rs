mod commands;
mod errors;
mod trust_stores;
mod utils;
mod x509;
use clap::{Parser, Subcommand};
use commands::generate::generate;
use std::env;

#[derive(Parser)]
#[clap(
    name = "A simple config tool to make locally trusted X.509 development certificates for your domains",
    version = "0.1.2",
    author = "Shubham Singh"
)]
struct CLI {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[clap(name = "generate")]
    Generate {
        #[arg(short = 'd', long = "domain")]
        domains: Vec<String>,

        #[arg(name = "no-ca", long)]
        noca: bool,

        #[clap(name = "csr", long)]
        csr: Option<String>,

        #[arg(name = "certfile", long)]
        certfile: Option<String>,

        #[arg(name = "keyfile", long)]
        keyfile: Option<String>,

        #[arg(short = 'c', long = "country")]
        country: Option<String>,

        #[arg(long = "cn")]
        commonname: Option<String>,

        #[arg(short = 's', long = "state")]
        state: Option<String>,

        #[arg(short = 'o', long = "output")]
        output: Option<String>,

        #[arg(long = "req-only")]
        request: bool,
    },
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    for arg in args.iter_mut() {
        if arg == "-cn" {
            *arg = "--cn".to_string();
        }
    }

    let args: CLI = CLI::parse_from(args);

    if let Some(command) = args.command {
        match command {
            Commands::Generate {
                domains,
                noca,
                csr,
                certfile,
                keyfile,
                country,
                commonname,
                state,
                output,
                request,
            } => {
                if certfile.is_some() != keyfile.is_some() {
                    if certfile.is_some() {
                        eprintln!(
                            "Error: Please provide corresponding `--keyfile` to the certificate provided"
                        );
                        std::process::exit(1);
                    }
                    eprintln!(
                        "Error: Please provide corresponding `--certfile` to the keyfile provided"
                    );
                    std::process::exit(1);
                }

                if request && csr.is_some() {
                    eprint!("Error: `--req-only` and `csr` are incompatible. You can't generate requests from a request certificate.");
                    std::process::exit(1);
                }

                let _ = generate(
                    domains, noca, csr, certfile, keyfile, country, commonname, state, output,
                    request,
                );
            }
        }
    }
}
