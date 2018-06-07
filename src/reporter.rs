use capstone::{Insn, InsnDetail};
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_void;

use arch::MachineDescriptor;
use decoder::InstructionVisitor;

type OpaquePtr = *const c_void;
type CharPtr = *const c_char;

pub type PrintCallback = extern "C" fn(output: OpaquePtr, format: CharPtr, ...);
pub type EventCallback = extern "C" fn(output: OpaquePtr, event: CharPtr, data: OpaquePtr);

pub enum InstructionReporterEvent {
    Begin(u64),
    BeginInstruction(u64),
    EndInstruction(u64),
    End(u64),
    MachineInfo(MachineDescriptor),
}

pub struct InstructionReporter {
    pub print_callback: PrintCallback,
    pub print_callback_data: *const c_void,
    pub event_callback: EventCallback,
    pub event_callback_data: *const c_void,
}

const BEGIN_KEY: &str = "insns";
const BEGIN_INSN_KEY: &str = "insn";
const END_INSN_KEY: &str = "/insn";
const END_KEY: &str = "/insns";
const MACH_INFO_KEY: &str = "mach name='%s'/";

impl InstructionReporter {
    pub fn handle_event(&mut self, event: InstructionReporterEvent) {
        use self::InstructionReporterEvent::*;

        match event {
            Begin(addr) => self.event_at_addr(BEGIN_KEY, addr),
            BeginInstruction(addr) => self.event_at_addr(BEGIN_INSN_KEY, addr),
            EndInstruction(addr) => self.event_at_addr(END_INSN_KEY, addr),
            End(addr) => self.event_at_addr(END_KEY, addr),
            MachineInfo(mach) => self.event(MACH_INFO_KEY, mach.to_string()),
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

impl InstructionVisitor for InstructionReporter {
    fn visit_begin(&mut self, machine: MachineDescriptor, addr: u64) {
        self.handle_event(InstructionReporterEvent::Begin(addr));
        self.handle_event(InstructionReporterEvent::MachineInfo(machine));
    }

    fn visit_end(&mut self, addr: u64) {
        self.handle_event(InstructionReporterEvent::End(addr))
    }

    fn visit_instruction(&mut self, instruction: &Insn, _detail: InsnDetail) {
        use self::InstructionReporterEvent::*;

        self.handle_event(BeginInstruction(instruction.address()));

        if let (Some(mnemonic), Some(operands)) = (instruction.mnemonic(), instruction.op_str()) {
            self.print(format!("{} {}", mnemonic, operands));
        }

        self.handle_event(EndInstruction(
            instruction.address() + (instruction.bytes().len()) as u64,
        ));
    }
}
