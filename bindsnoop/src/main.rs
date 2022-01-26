mod bpf;
use anyhow::Result;
use bpf::*;
use libbpf_rs::{MapFlags, PerfBufferBuilder};
use plain::Plain;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;
use std::time::Duration;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
struct Command {
    /// Process ID to trace
    #[structopt(short = "p", default_value = "0", value_name = "PID")]
    pid: i32,
    /// Include errors on output.
    #[structopt(short = "x")]
    fails: bool,
    /// Comma-separated list of ports to trace.
    #[structopt(short = "P", use_delimiter = true)]
    port: Vec<u16>,
}

#[repr(C)]
#[derive(Default, Debug)]
struct Event {
    pub addr: u128,
    pub ts_us: u64,
    pub pid: u32,
    pub bound_dev_if: u32,
    pub ret: u32,
    pub port: u16,
    pub opts: u8,
    pub proto: u8,
    pub ver: u8,
    pub task: [u8; 16],
}

unsafe impl Plain for Event {}

fn main() -> Result<()> {
    let opts: Command = Command::from_args();

    let skel_builder = BindsnoopSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;
    open_skel.rodata().target_pid = opts.pid;
    open_skel.rodata().ignore_errors = opts.fails;
    open_skel.rodata().filter_by_port = !opts.port.is_empty();

    let mut skel = open_skel.load()?;

    if !opts.port.is_empty() {
        for port in opts.port {
            let key = (port as u16).to_ne_bytes();
            let val = 1_u16.to_ne_bytes();
            skel.maps_mut()
                .ports()
                .update(&key, &val, MapFlags::ANY)?;
        }
    }
    skel.attach()?;
    println!(
        "{:6} {:16} {:3} {:6} {:6} {:3} {:6} {:48}",
        "PID", "COMM", "RET", "PROTO", "OPTS", "IF", "PORT", "ADDR"
    );

    let perf = PerfBufferBuilder::new(skel.maps().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;
    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}

fn handle_event(_cpu: i32, data: &[u8]) {
    let mut event: Event = Event::default();
    plain::copy_from_bytes(&mut event, data).expect("Data buffer was too short");
    let addr = if event.ver == 4 {
        IpAddr::V4(Ipv4Addr::from((event.addr as u32).to_be()))
    } else {
        IpAddr::V6(Ipv6Addr::from(event.addr.to_be()))
    };
    let proto = if event.proto == 6 {
        "TCP"
    } else if event.proto == 17 {
        "UDP"
    } else {
        "UNK"
    };
    let opts_array = ['F', 'T', 'N', 'R', 'r'];
    let opts = {
        opts_array
            .iter()
            .enumerate()
            .map(|(i, &c)| if ((1 << i) & event.opts) == 0 { '.' } else { c })
            .collect::<String>()
    };
    let task = str::from_utf8(&event.task).unwrap().trim_end_matches('\0');
    println!(
        "{:<6} {:16} {:3} {:<6} {:<6} {:3} {:<6} {:48}",
        event.pid, task, event.ret, proto, opts, event.bound_dev_if, event.port, addr
    );
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}
