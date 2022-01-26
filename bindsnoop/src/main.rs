mod bpf;
use anyhow::Result;
use bpf::*;
use libbpf_rs::{MapFlags, PerfBufferBuilder};
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

fn main() -> Result<()> {
    let opts: Command = Command::from_args();

    let skel_builder = BindsnoopSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;
    open_skel.rodata().target_pid = opts.pid;
    open_skel.rodata().ignore_errors = opts.fails;
    open_skel.rodata().filter_by_port = !opts.port.is_empty();

    let mut skel = open_skel.load()?;

    if !opts.port.is_empty() {
        for (i, value) in opts.port.iter().enumerate() {
            let key = i.to_ne_bytes();
            let value = value.to_ne_bytes();
            skel.maps_mut()
                .ports()
                .update(&key, &value, MapFlags::ANY)?;
        }

        /*
            map.update(key, value, flags)
            if (target_ports) {
            port_map_fd = bpf_map__fd(obj->maps.ports);
            port = strtok(target_ports, ",");
            while (port) {
                port_num = strtol(port, NULL, 10);
                bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
                port = strtok(NULL, ",");
            }
        }
        */
    }
    skel.attach()?;

    let perf = PerfBufferBuilder::new(skel.maps().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;
    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}

fn handle_event(_cpu: i32, data: &[u8]) {
    
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}
