#![no_std]
#![no_main]
use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use core::mem;
use memoffset::offset_of;
mod vmlinux;
use vmlinux::{ethhdr, iphdr};

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();

#[xdp(name = "xdp")]
pub fn xdp(ctx: XdpContext) -> u32 {
    match unsafe { try_xdp(ctx) } {
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

#[inline(always)]
fn is_ipv4(ctx: &XdpContext) -> Result<bool, ()> {
    // Get protocol type of ethernet frame
    let h_proto = u16::from_be(unsafe { *ptr_at(&ctx, offset_of!(ethhdr, h_proto))? });
    // Check if it's ipv4, if isn't then allow it.
    if h_proto == ETH_P_IP {
        return Ok(true);
    }
    Ok(false)
}

unsafe fn try_xdp(ctx: XdpContext) -> Result<u32, ()> {
    if is_ipv4(&ctx)? {
        let protocol_type = u8::from_be(*ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, protocol))?);
        if protocol_type == IPPROTO_ICMP {
            return Ok(xdp_action::XDP_DROP);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
