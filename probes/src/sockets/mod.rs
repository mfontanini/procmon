#[derive(Clone, Copy)]
#[repr(C)]
pub struct ConnectEvent {
    pub fd: i32,
    pub port: u16,
    pub _padding: [u8; 2],
    pub address: IpAddress,
}

impl ConnectEvent {
    pub fn new(fd: i32, port: u16, address: IpAddress) -> Self {
        Self {
            fd,
            port,
            address,
            _padding: [0; 2],
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub enum IpAddress {
    V4(u32),
}

#[cfg(not(feature = "no-std"))]
impl From<IpAddress> for std::net::IpAddr {
    fn from(address: IpAddress) -> Self {
        match address {
            IpAddress::V4(address) => Self::V4(address.into()),
        }
    }
}
