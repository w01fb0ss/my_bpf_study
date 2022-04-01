#[path = "bpf/xdp_drop.skel.rs"]
mod bpf;
use bpf::*;

use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{thread, time};

fn main() -> Result<()> {
    let skel_builder: XdpDropSkelBuilder = XdpDropSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    let link = skel.progs_mut().xdp_drop_icmp().attach_xdp(2)?;

    skel.links = XdpDropLinks {
        xdp_drop_icmp: Some(link),
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        eprint!(".");
        thread::sleep(time::Duration::from_secs(1));
    }

    Ok(())
}
