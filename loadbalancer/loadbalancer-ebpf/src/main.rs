#![no_std]
#![no_main]

mod bindings;

use aya_bpf::{
    bindings::xdp_action, macros::map, macros::xdp, maps::PerfEventArray, programs::XdpContext,
};
use bindings::{ethhdr, iphdr};
use core::mem;
use loadbalancer_common::PacketLog;
use memoffset::offset_of;

const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[xdp(name = "loadbalancer")]
pub fn loadbalancer(ctx: XdpContext) -> u32 {
    match unsafe { try_loadbalancer(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

unsafe fn try_loadbalancer(ctx: XdpContext) -> Result<u32, ()> {
    let h_proto = u16::from_be(*ptr_at(&ctx, offset_of!(ethhdr, h_proto))?);
    if h_proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let source = u32::from_be(*ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))?);
    let dst = u32::from_be(*ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))?);
    let log_entry = PacketLog {
        src_addr: source,
        dst_addr: dst,
        action: xdp_action::XDP_PASS,
    };
    EVENTS.output(&ctx, &log_entry, 0);
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
