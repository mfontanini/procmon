#![no_std]
#![no_main]
use probes::sockets::*;
use redbpf_probes::uprobe::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map("connect_event")]
static mut connect_event: PerfMap<ConnectEvent> = PerfMap::with_max_entries(1024);

#[uprobe]
fn connect(regs: Registers) {
    let addr = unsafe { &*(regs.parm2() as *const sockaddr_in) };
    process_connect_ipv4(regs, addr);
}

#[inline]
fn process_connect_ipv4(regs: Registers, addr: &sockaddr_in) -> Option<()> {
    let fd = regs.parm1() as i32;
    let port = u16::from_be(addr.sin_port()?);
    let raw_address = addr.sin_addr()?.s_addr()?;
    let address = IpAddress::V4(u32::from_be(raw_address));
    let event = ConnectEvent::new(fd, port, address);
    unsafe {
        connect_event.insert(regs.ctx, &event);
    }
    Some(())
}
