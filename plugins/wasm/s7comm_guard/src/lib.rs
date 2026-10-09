#![no_std]
use core::panic::PanicInfo;
use sentinel_sdk_rs::{PacketView, Verdict};

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

// Exported C-ABI entry point expected by Sentinel WasmSandbox
#[no_mangle]
pub extern "C" fn sentinel_dissect(pkt_ptr: *const u8, len: u32) -> i32 {
    let pkt = unsafe { PacketView::from_raw(pkt_ptr, len as usize) };

    // S7Comm packets must be at least 18 bytes (TPKT + COTP + S7 Header)
    if pkt.len() < 18 {
        return Verdict::Pass as i32;
    }

    // Byte 0: TPKT Version (0x03)
    // Byte 4: COTP Length
    // Byte 7: S7 Protocol ID (0x32 = Siemens S7Comm)
    if pkt.get_u8(0) == Some(0x03) && pkt.get_u8(7) == Some(0x32) {
        // Offset 9: S7 Message Type (0x01 = Job Request)
        // Offset 17: S7 Function Code (0x29 = CPU STOP Command)
        if let Some(msg_type) = pkt.get_u8(9) {
            if let Some(func_code) = pkt.get_u8(17) {
                if msg_type == 0x01 && func_code == 0x29 {
                    // Unauthorized CPU Stop request targeting S7-1200 / S7-1500 PLC -> DROP!
                    return Verdict::KernelDrop as i32;
                }
            }
        }
    }

    Verdict::Pass as i32
}