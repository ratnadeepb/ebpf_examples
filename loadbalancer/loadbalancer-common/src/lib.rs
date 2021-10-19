#![no_std]

#[repr(C)]
pub struct PacketLog {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub action: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
