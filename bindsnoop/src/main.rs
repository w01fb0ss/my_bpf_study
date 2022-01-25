mod bpf;
use anyhow::Result;
use bpf::*;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Command {
    
}

fn main() -> Result<()> {
    let skel_builder = BindsnoopSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    skel.attach()?;
    Ok(())
}
