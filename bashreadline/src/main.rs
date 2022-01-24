mod bpf;
use bpf::*;

use anyhow::Result;
use chrono::Local;
use core::time::Duration;
use libbpf_rs::PerfBufferBuilder;
use object::{Object, ObjectSymbol};
use plain::Plain;
use std::fs;
use std::io::Read;
use std::str;

const BINARY_NAME: &str = "/bin/bash";
const SYM_NAME: &str = "readline";

#[macro_use]
extern crate lazy_static;

mod timer {
    lazy_static! {
        pub static ref TIMER: std::time::Instant = std::time::Instant::now();
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Event {
    pub pid: u64,
    pub str: [u8; 80],
}

unsafe impl Plain for Event {}

impl Event {
    fn copy_from_bytes(buf: &[u8]) -> Event {
        let mut e = Event {
            pid: 0,
            str: [0; 80],
        };
        e.copy_from_bytes(buf).expect("buffer is short");
        e
    }
}

fn handle_event(_cpu: i32, mut data: &[u8]) {
    let now = Local::now();
    let mut buf = [0; 128];
    let n = data.read(&mut buf).unwrap();
    let event = Event::copy_from_bytes(&buf[0..n]);

    let s: Vec<u8> = event.str.iter().take_while(|x| **x != 0).cloned().collect();

    println!(
        "{:8} {:<6} {:?}",
        now.format("%H:%M:%S"),
        // event.uid,
        event.pid,
        String::from_utf8(s).unwrap()
    );
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {} events on CPU {}", count, cpu);
}

fn main() -> Result<()> {
    let skel_builder = BashreadlineSkelBuilder::default();
    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;

    let bin_data = fs::read(BINARY_NAME).unwrap();
    let obj_file = object::File::parse(&*bin_data).unwrap();
    let mut offset = 0;
    for s in obj_file.dynamic_symbols() {
        if s.name().unwrap() == SYM_NAME {
            offset = s.address();
        }
    }
    // skel.attach()?;
    let _link = skel
        .obj
        .prog_mut("printret")
        .unwrap()
        .attach_uprobe(true, -1, BINARY_NAME, offset as usize)
        .unwrap();

    println!("{:8} {:6} {:}", "TIME", "PID", "COMMAND");
    timer::TIMER.elapsed();
    let perf = PerfBufferBuilder::new(skel.maps().events())
        .sample_cb(handle_event)
        .lost_cb(handle_lost_events)
        .build()?;
    loop {
        perf.poll(Duration::from_millis(100))?;
    }
}
