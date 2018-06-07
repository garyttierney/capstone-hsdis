extern crate capstone;

use std::os::raw::c_char;
use std::os::raw::c_void;
use std::slice;

mod arch;
mod decoder;
mod reporter;

#[no_mangle]
pub extern "C" fn decode_instructions(
    start: *const u8,
    end: *const u8,
    event_callback: reporter::EventCallback,
    event_callback_data: *const c_void,
    print_callback: reporter::PrintCallback,
    print_callback_data: *const c_void,
    _options: *const c_char,
) {
    let address = start as u64;
    let data_len = end as usize - start as usize;
    let data = unsafe { slice::from_raw_parts(start, data_len) };

    let decoder = decoder::InstructionDecoder::default();
    let mut reporter = reporter::InstructionReporter {
        print_callback,
        print_callback_data,
        event_callback,
        event_callback_data,
    };

    let decode_result = decoder.decode(address, data, &mut reporter);
    if decode_result.is_err() {
        eprintln!(
            "Error occurred during decoding: {}",
            decode_result.unwrap_err()
        );
    }
}
