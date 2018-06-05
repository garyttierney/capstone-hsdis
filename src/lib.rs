extern crate capstone;

use capstone::{Arch, Insn, Mode};
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::slice;

mod arch;
mod decoder;

pub type PrintCallback = extern "C" fn(data: *const c_void, format: *const c_char, ...);
pub type EventCallback = extern "C" fn(data: *const c_void, value: *const c_char, end: *const u8);

struct InstructionReporter {
    print_callback: PrintCallback,
    print_callback_data: *const c_void,
    event_callback: EventCallback,
    event_callback_data: *const c_void,
}

impl decoder::InstructionVisitor for InstructionReporter {
    fn visit(&mut self, instruction: &Insn, arch: Arch, mode: Mode) {
        unimplemented!()
    }
}

#[no_mangle]
pub extern "C" fn decode_instructions(
    start: *const u8,
    end: *const u8,
    event_callback: EventCallback,
    event_callback_data: *const c_void,
    print_callback: PrintCallback,
    print_callback_data: *const c_void,
    options: *const c_char,
) {
    let data_len = end as usize - start as usize;
    let data = unsafe { slice::from_raw_parts(start, data_len) };

    let decoder = decoder::InstructionDecoder::default();
    let mut reporter = InstructionReporter {
        print_callback,
        print_callback_data,
        event_callback,
        event_callback_data,
    };

    decoder.decode(data, &mut reporter);
}
