#![no_std]

// Action Verdicts matching Sentinel C ABI
#[repr(i32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass = 0,
    InspectDeep = 1,
    Alert = 2,
    KernelDrop = 3,
    HoneypotDivert = 4,
}

// Zero-copy, non-owning slice viewer over incoming raw packet memory
pub struct PacketView<'a> {
    data: &'a [u8],
}

impl<'a> PacketView<'a> {
    #[inline(always)]
    pub unsafe fn from_raw(ptr: *const u8, len: usize) -> Self {
        if ptr.is_null() || len == 0 {
            Self { data: &[] }
        } else {
            Self {
                data: core::slice::from_raw_parts(ptr, len),
            }
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[inline(always)]
    pub fn get_u8(&self, offset: usize) -> Option<u8> {
        self.data.get(offset).copied()
    }

    #[inline(always)]
    pub fn read_be16(&self, offset: usize) -> Option<u16> {
        if offset + 2 <= self.data.len() {
            let bytes = [self.data[offset], self.data[offset + 1]];
            Some(u16::from_be_bytes(bytes))
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn read_be32(&self, offset: usize) -> Option<u32> {
        if offset + 4 <= self.data.len() {
            let bytes = [
                self.data[offset],
                self.data[offset + 1],
                self.data[offset + 2],
                self.data[offset + 3],
            ];
            Some(u32::from_be_bytes(bytes))
        } else {
            None
        }
    }

    #[inline(always)]
    pub fn slice(&self, start: usize, len: usize) -> Option<&'a [u8]> {
        if start + len <= self.data.len() {
            Some(&self.data[start..start + len])
        } else {
            None
        }
    }
}

// Host capability imports (Wasm3 'env' namespace)
extern "C" {
    pub fn sentinel_host_log(level: u32, msg_ptr: *const u8);
    pub fn sentinel_host_drop_ipv4(ipv4: u32, duration_sec: u32) -> i32;
    pub fn sentinel_host_emit_metric(metric_ptr: *const u8, delta: u64);
    pub fn sentinel_host_monotonic_ns() -> u64;
}