#![no_std]
#![no_main]
use probes::fd::*;
use redbpf_probes::uprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map("connect_event")]
static mut connect_events: PerfMap<SocketConnectEvent> = PerfMap::with_max_entries(1024);

#[map("fd_write_event")]
static mut fd_write_events: PerfMap<FdWriteEvent> = PerfMap::with_max_entries(1024);

#[inline]
fn process_connect_ipv4(regs: Registers, addr: &sockaddr_in) -> Option<()> {
    let fd = regs.parm1() as i32;
    let port = u16::from_be(addr.sin_port()?);
    let raw_address = addr.sin_addr()?.s_addr()?;
    let address = IpAddress::V4(u32::from_be(raw_address));
    let event = SocketConnectEvent::new(fd, port, address);
    unsafe {
        connect_events.insert(regs.ctx, &event);
    }
    Some(())
}

#[inline]
fn write_handler(regs: Registers) {
    let fd = regs.parm1() as i32;
    let bytes = regs.parm3();
    let event = FdWriteEvent::new(fd, bytes);
    unsafe {
        fd_write_events.insert(regs.ctx, &event);
    }
}

// uprobes

#[uprobe]
fn connect(regs: Registers) {
    let addr = unsafe { &*(regs.parm2() as *const sockaddr_in) };
    process_connect_ipv4(regs, addr);
}

#[uprobe]
fn send(regs: Registers) {
    write_handler(regs);
}

#[uprobe]
fn write(regs: Registers) {
    write_handler(regs);
}
