extern crate capstone;

use capstone::prelude::ArchDetail;
use capstone::{Arch, Insn, InsnDetail, Mode};
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;
use std::slice;

mod arch;
mod decoder;

pub type PrintCallback = extern "C" fn(output: *const c_void, format: *const c_char, ...);
pub type EventCallback =
    extern "C" fn(output: *const c_void, event: *const c_char, data: *const c_void);

pub enum InstructionReporterEvent {
    Begin(u64),
    BeginInstruction(u64),
    EndInstruction(u64),
    End(u64),
    MachineInfo(arch::MachineDescriptor),
}

struct InstructionReporter {
    print_callback: PrintCallback,
    print_callback_data: *const c_void,
    event_callback: EventCallback,
    event_callback_data: *const c_void,
}

const BEGIN_KEY: &str = "insns";
const BEGIN_INSN_KEY: &str = "insn";
const END_INSN_KEY: &str = "/insn";
const END_KEY: &str = "/insns";
const MACH_INFO_KEY: &str = "mach name='%s'/";

trait InstructionReporterEventData {}

impl InstructionReporter {
    pub fn handle_event(&mut self, event: InstructionReporterEvent) {
        use InstructionReporterEvent::*;

        match event {
            Begin(addr) => self.event_at_addr(BEGIN_KEY, addr),
            BeginInstruction(addr) => self.event_at_addr(BEGIN_INSN_KEY, addr),
            EndInstruction(addr) => self.event_at_addr(END_INSN_KEY, addr),
            End(addr) => self.event_at_addr(END_KEY, addr),
            MachineInfo(mach) => self.event(MACH_INFO_KEY, mach.to_string()),
            _ => {}
        }
    }

    fn print<S>(&mut self, data: S)
    where
        S: Into<Vec<u8>>,
    {
        let data_cstr = CString::new(data.into()).expect("Unable to allocate c-strign");

        (self.print_callback)(self.print_callback_data, data_cstr.as_ptr());
    }

    fn event_at_addr<S>(&mut self, data: S, address: u64)
    where
        S: Into<Vec<u8>>,
    {
        let name_cstr = CString::new(data.into()).unwrap();

        (self.event_callback)(
            self.event_callback_data,
            name_cstr.as_ptr(),
            address as *const c_void,
        );
    }

    fn event<E, D>(&mut self, event: E, data: D)
    where
        E: Into<Vec<u8>>,
        D: Into<Vec<u8>>,
    {
        let event_cstr = CString::new(event.into()).unwrap();
        let data_cstr = CString::new(data.into()).unwrap();

        (self.event_callback)(
            self.event_callback_data,
            event_cstr.as_ptr(),
            data_cstr.as_ptr() as *const c_void,
        );
    }
}

impl decoder::InstructionVisitor for InstructionReporter {
    fn visit_begin(&mut self, machine: arch::MachineDescriptor, addr: u64) {
        self.handle_event(InstructionReporterEvent::Begin(addr));
        self.handle_event(InstructionReporterEvent::MachineInfo(machine));
    }

    fn visit_end(&mut self, addr: u64) {
        self.handle_event(InstructionReporterEvent::End(addr))
    }

    fn visit_insn(&mut self, instruction: &Insn, detail: &InsnDetail, arch: &ArchDetail) {
        use InstructionReporterEvent::*;

        self.handle_event(BeginInstruction(instruction.address()));

        if let (Some(mnemonic), Some(operands)) = (instruction.mnemonic(), instruction.op_str()) {
            self.print(format!("{} {}", mnemonic, operands));
        }

        self.handle_event(EndInstruction(
            instruction.address() + (instruction.bytes().len()) as u64,
        ));
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
    let addr = start as u64;
    let data_len = end as usize - start as usize;
    let data = unsafe { slice::from_raw_parts(start, data_len) };

    let decoder = decoder::InstructionDecoder::default();
    let mut reporter = InstructionReporter {
        print_callback,
        print_callback_data,
        event_callback,
        event_callback_data,
    };

    decoder.decode(addr, data, &mut reporter);
}
