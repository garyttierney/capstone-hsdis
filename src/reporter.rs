use capstone::{Insn, InsnDetail};
use std::error;
use std::ffi;
use std::fmt;
use std::os::raw::c_char;
use std::os::raw::c_void;

use arch::MachineDescriptor;
use decoder::InstructionVisitor;
use decoder::InstructionVisitorError;

type OpaquePtr = *const c_void;
type CharPtr = *const c_char;

pub type PrintCallback = extern "C" fn(output: OpaquePtr, format: CharPtr, ...);
pub type EventCallback = extern "C" fn(output: OpaquePtr, event: CharPtr, data: OpaquePtr) -> usize;

/// A HotSpot disassembler event.
enum Event {
    /// Denotes the beginning of disassembly at the given address.
    Begin(usize),

    /// Denotes the beginning of an instruction being decoded at the given address.
    BeginInstruction(usize),

    /// Denotes the end of an instruction being decoded with its end address.
    EndInstruction(usize),

    /// Denotes that disassembly has completed at the given address.
    End(usize),

    /// Denotes that disassembly is being done for the given machine.
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

trait EventData: Sized {
    fn get_ptr(&self) -> *const c_void;
}

impl EventData for ffi::CString {
    fn get_ptr(&self) -> *const c_void {
        self.as_ptr() as *const c_void
    }
}

impl EventData for usize {
    fn get_ptr(&self) -> *const c_void {
        *self as *const c_void
    }
}

impl ToString for Event {
    fn to_string(&self) -> String {
        use self::Event::*;

        let key = match *self {
            Begin(_) => BEGIN_KEY,
            BeginInstruction(_) => BEGIN_INSN_KEY,
            EndInstruction(_) => END_INSN_KEY,
            End(_) => END_KEY,
            MachineInfo(_) => MACH_INFO_KEY,
        };

        String::from(key)
    }
}

#[derive(Debug)]
pub enum InstructionReporterError {
    FfiParametersError(ffi::NulError),
}

#[doc(hidden)]
impl From<ffi::NulError> for InstructionReporterError {
    fn from(err: ffi::NulError) -> Self {
        InstructionReporterError::FfiParametersError(err)
    }
}

impl InstructionVisitorError for InstructionReporterError {}

#[doc(hidden)]
impl error::Error for InstructionReporterError {
    fn description(&self) -> &str {
        match *self {
            InstructionReporterError::FfiParametersError(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            InstructionReporterError::FfiParametersError(ref err) => Some(err),
        }
    }
}
#[doc(hidden)]
impl fmt::Display for InstructionReporterError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            InstructionReporterError::FfiParametersError(ref err) => {
                write!(f, "FFI call error: {}", err)
            }
        }
    }
}

impl InstructionReporter {
    fn handle_event(&mut self, event: Event) -> Result<bool, InstructionReporterError> {
        use self::Event::*;

        let event_key = event.to_string();
        let result = match event {
            Begin(addr) | BeginInstruction(addr) | EndInstruction(addr) | End(addr) => {
                self.report_event(event_key, addr)
            }
            MachineInfo(mach) => {
                self.report_event(event_key, ffi::CString::new(mach.to_string()).unwrap())
            }
        };

        result.map_err(|e| e.into())
    }

    /// Report a message back to the HotSpot dissassembler to print to the compiler log.
    fn print<S>(&mut self, data: S) -> Result<(), ffi::NulError>
    where
        S: Into<Vec<u8>>,
    {
        let data_cstr = ffi::CString::new(data.into())?;

        Ok((self.print_callback)(
            self.print_callback_data,
            data_cstr.as_ptr(),
        ))
    }

    /// Report a disassembly event to the HotSpot disassembler.
    fn report_event<S, D>(&mut self, key: S, data: D) -> Result<bool, ffi::NulError>
    where
        S: Into<Vec<u8>>,
        D: EventData,
    {
        let event = ffi::CString::new(key.into())?;
        let data = data.get_ptr();
        let result = (self.event_callback)(self.event_callback_data, event.as_ptr(), data);

        Ok(result != 0)
    }
}

impl InstructionVisitor<InstructionReporterError> for InstructionReporter {
    fn visit_begin(
        &mut self,
        machine: MachineDescriptor,
        addr: usize,
    ) -> Result<(), InstructionReporterError> {
        self.handle_event(Event::Begin(addr))?;
        self.handle_event(Event::MachineInfo(machine))?;

        Ok(())
    }

    fn visit_end(&mut self, addr: usize) -> Result<(), InstructionReporterError> {
        self.handle_event(Event::End(addr))?;

        Ok(())
    }

    fn visit_instruction(
        &mut self,
        instruction: &Insn,
        _detail: InsnDetail,
    ) -> Result<(), InstructionReporterError> {
        let instruction_start = instruction.address() as usize;
        let instruction_end = instruction_start + instruction.bytes().len();

        self.handle_event(Event::BeginInstruction(instruction_start))?;

        if let Some(mnemonic) = instruction.mnemonic() {
            let mut disassembly = mnemonic.to_string();

            if let Some(operands_disassembly) = instruction.op_str() {
                disassembly = format!("{} {}", disassembly, operands_disassembly);
            }

            self.print(disassembly)?;
        }

        self.handle_event(Event::EndInstruction(instruction_end))?;

        Ok(())
    }
}
