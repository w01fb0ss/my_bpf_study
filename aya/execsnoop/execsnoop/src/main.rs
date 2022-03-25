use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use bytes::BytesMut;
use execsnoop_common::Event;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use structopt::StructOpt;
use tokio::{signal, task};
// test git

#[derive(Debug, StructOpt)]
struct Opt {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _opt = Opt::from_args();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/execsnoop"
    ))?;
    let program: &mut TracePoint = bpf.program_mut("sys_enter_execve").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let program: &mut TracePoint = bpf.program_mut("sys_exit_execve").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_execve")?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr().cast::<Event>();
                    let data = unsafe { ptr.read_unaligned() };
                    println!("{:?}", data);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
