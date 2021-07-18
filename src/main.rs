use futures::StreamExt;
use log::{error, info, LevelFilter};
use probes::fd::{FdWriteEvent, SocketConnectEvent};
use redbpf::load::{Loaded, Loader};
use simple_logger::SimpleLogger;
use std::collections::HashMap;
use std::net::IpAddr;
use std::{env, process, ptr};

fn sockets_probe_code() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/target/bpf/programs/fd/fd.elf"))
}

fn process_connect_event(event: SocketConnectEvent) {
    let address: IpAddr = event.address.into();
    info!(
        "Connect event, fd: {}, address: {}, port: {}",
        event.fd, address, event.port
    );
}

fn process_fd_write_event(event: FdWriteEvent) {
    info!("FD write event, fd: {}, bytes: {}", event.fd, event.bytes);
}

fn proxy<T, F>(handler: F) -> Box<dyn Fn(Box<[u8]>) -> ()>
where
    F: Fn(T) -> () + 'static,
{
    let proxy_handler = move |event: Box<[u8]>| {
        let parsed_event = unsafe { ptr::read(event.as_ptr() as *const T) };
        handler(parsed_event)
    };
    Box::new(proxy_handler)
}

async fn process_events(mut loaded: Loaded) {
    let mut handlers = HashMap::new();
    handlers.insert("connect_event", proxy(process_connect_event));
    handlers.insert("fd_write_event", proxy(process_fd_write_event));
    while let Some((name, events)) = loaded.events.next().await {
        if let Some(handler) = handlers.get(name.as_str()) {
            for event in events {
                handler(event);
            }
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
