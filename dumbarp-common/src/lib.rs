#![no_std]

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ArpKey {
    pub ifindex: u32,
    pub ip: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ArpKey {}
