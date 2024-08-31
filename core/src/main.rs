mod errors;
mod reference;
pub mod utils;
mod x509;
use clap::{Parser, Subcommand};
use std::env;

#[derive(Parser)]
#[clap(
    name = "A simple config tool to make locally trusted X.509 development certificates for your domains",
    version = "0.0.1",
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

        #[clap(short, long)]
        debug: bool,

        #[clap(name = "csr", long)]
        csr: Option<String>,

        #[arg(name = "certfile", long)]
        certfile: Option<String>,

        #[arg(name = "keyfile", long)]
        keyfile: Option<String>,

        #[arg(long = "org")]
        organization: Option<String>,

        #[arg(short = 'c', long = "country")]
        country: Option<String>,

        #[arg(long = "cn")]
        commonname: Option<String>,

        #[arg(short = 's', long = "state")]
        state: Option<String>,

        #[arg(short = 'o', long = "output")]
        output: Option<String>,
    },
}

fn main() {
    let mut args: Vec<String> = env::args().collect();
    for arg in args.iter_mut() {
        if arg == "-cn" {
            *arg = "--cn".to_string();
        }
        if arg == "-org" {
            *arg = "--org".to_string();
        }
    }

    let args: CLI = CLI::parse_from(args);

    if let Some(command) = args.command {
        match command {
            Commands::Generate {
                domains,
                noca,
                debug,
                csr,
                certfile,
                keyfile,
                organization,
                country,
                commonname,
                state,
                output,
            } => {
                if certfile.is_some() != keyfile.is_some() {
                    if certfile.is_some() {
                        eprintln!("Error: Please provide corresponding `--keyfile` to the provided Certificate.");
                    }
                    eprintln!(
                        "Error: Please provide corresponding `--certfile` to the provided KeyFile."
                    );
                    std::process::exit(1);
                }

                for domain in domains {
                    println!("Domain: {}", domain);
                }
                println!("No CA: {}", noca);
                println!("Debug mode: {}", debug);

                if let Some(csr) = csr {
                    println!("CSR file: {}", csr);
                }
                if let Some(certfile) = certfile {
                    println!("Certificate file: {}", certfile);
                }
                if let Some(keyfile) = keyfile {
                    println!("Key file: {}", keyfile);
                }
                if let Some(organization) = organization {
                    println!("Organization: {}", organization);
                }
                if let Some(country) = country {
                    println!("Country: {}", country);
                }
                if let Some(commonname) = commonname {
                    println!("Common Name: {}", commonname);
                }
                if let Some(state) = state {
                    println!("State : {}", state);
                }
                if let Some(output) = output {
                    println!("Output: {}", output);
                }
            }
        }
    }
}
