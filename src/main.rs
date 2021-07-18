use futures::StreamExt;
use log::{error, info, LevelFilter};
use probes::sockets::ConnectEvent;
use redbpf::load::{Loaded, Loader};
use simple_logger::SimpleLogger;
use std::net::IpAddr;
use std::{env, process, ptr};

fn sockets_probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/sockets/sockets.elf"
    ))
}

async fn process_events(mut loaded: Loaded) {
    while let Some((name, events)) = loaded.events.next().await {
        match name.as_str() {
            "connect_event" => {
                for event in events {
                    let event = unsafe { ptr::read(event.as_ptr() as *const ConnectEvent) };
                    let address: IpAddr = event.address.into();
                    info!(
                        "Connect event, fd: {}, address: {}, port: {}",
                        event.fd, address, event.port
                    );
                }
            }
            _ => {}
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .unwrap();
    let args: Vec<String> = env::args().collect();
    let pid = args.get(1).unwrap_or_else(|| {
        eprintln!("PID must be specified");
        process::exit(1);
    });
    let pid = pid.parse().unwrap_or_else(|err| {
        error!("Invalid PID {}", err);
        process::exit(1);
    });
    if unsafe { libc::geteuid() } != 0 {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    info!(
        "Loading sockets probe, program size is {}",
        sockets_probe_code().len()
    );
    let mut loaded = Loader::load(sockets_probe_code()).expect("Failed to load eBPF program");

    for prb in loaded.uprobes_mut() {
        if let Err(e) = prb.attach_uprobe(Some(&prb.name()), 0, "libc", Some(pid)) {
            error!("Failed to attach uprobe program '{}': {:?}", prb.name(), e);
            process::exit(1);
        }
    }

    process_events(loaded).await;

    Ok(())
}
