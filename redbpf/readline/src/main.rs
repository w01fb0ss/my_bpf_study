use futures::stream::StreamExt;
use probes::readline::ReadLineEvent;
use redbpf::load::Loader;
use std::{ffi::CStr, ptr};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

const BINARY_NAME: &str = "/bin/bash";

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/readline/readline.elf"
    ))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let mut loaded = Loader::load(probe_code()).expect("error on Loader::load");

    for uprobe in loaded.uprobes_mut() {
        uprobe
            .attach_uprobe(Some(&uprobe.name()), 0, BINARY_NAME, None)
            .expect(&format!(
                "error attaching uretprobe program {}",
                uprobe.name()
            ));
    }

    while let Some((map_name, events)) = loaded.events.next().await {
        if map_name == "ReadLines" {
            for event in events {
                let readline_event = unsafe { ptr::read(event.as_ptr() as *const ReadLineEvent) };
                unsafe {
                    let str = CStr::from_ptr(readline_event.str.as_ptr() as *const _);

                    println!(
                        "uid: {} --- pid: {}  ---  comm: {}",
                        readline_event.uid,
                        readline_event.pid,
                        str.to_string_lossy()
                    );
                };
            }
        }
    }
}
