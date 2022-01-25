mod bpf;
use anyhow::Result;
use bpf::*;
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
    #[structopt(short = "P", default_value = "80", use_delimiter = true)]
    port: Vec<u32>,
}

fn main() -> Result<()> {
    let opts: Command = Command::from_args();

    let skel_builder = BindsnoopSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;
    open_skel.rodata().target_pid = opts.pid;
    open_skel.rodata().ignore_errors = opts.fails;
    open_skel.rodata().filter_by_port = !opts.port.is_empty();

    let mut skel = open_skel.load()?;
    let mut maps = skel.maps_mut();
    let map = maps.ports();

    if !opts.port.is_empty() {

        /* TODO:
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
    Ok(())
}
