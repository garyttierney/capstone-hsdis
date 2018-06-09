use arch::MachineDescriptor;
use capstone;
use capstone::prelude::Capstone;
use capstone::{Insn, InsnDetail, NO_EXTRA_MODE};
use std::error;
use std::fmt;

/// A decoder that can disassemble machine code for a given [MachineDescriptor].
pub struct InstructionDecoder<'s> {
    /// A descriptor of the machine disassembly is being generated for.
    machine: MachineDescriptor,

    /// The instance of capstone being used for disassembly.
    cs: Capstone<'s>,
}

/// A type of error that can be emitted during machine code decoding.
#[derive(Debug)]
pub enum InstructionDecoderError<V: error::Error> {
    CapstoneError(capstone::Error),
    VisitorError(V),
}

#[doc(hidden)]
impl<V: InstructionVisitorError> From<capstone::Error> for InstructionDecoderError<V> {
    fn from(err: capstone::Error) -> Self {
        InstructionDecoderError::CapstoneError(err)
    }
}

#[doc(hidden)]
impl<V: InstructionVisitorError> From<V> for InstructionDecoderError<V> {
    fn from(err: V) -> Self {
        InstructionDecoderError::VisitorError(err)
    }
}

#[doc(hidden)]
impl<V: InstructionVisitorError> error::Error for InstructionDecoderError<V> {
    fn description(&self) -> &str {
        match *self {
            InstructionDecoderError::CapstoneError(ref err) => err.description(),
            InstructionDecoderError::VisitorError(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            InstructionDecoderError::CapstoneError(ref err) => Some(err),
            InstructionDecoderError::VisitorError(ref err) => Some(err),
        }
    }
}

#[doc(hidden)]
impl<V: InstructionVisitorError> fmt::Display for InstructionDecoderError<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            InstructionDecoderError::VisitorError(ref err) => {
                write!(f, "Error occurred in visitor: {}", err)
            }
            InstructionDecoderError::CapstoneError(ref err) => {
                write!(f, "Error occurred in capstone: {}", err)
            }
        }
    }
}

impl<'s> InstructionDecoder<'s> {
    /// Create a new [InstructionDecoder] that decodes instructions for the
    /// given [machine].
    pub fn new(machine: MachineDescriptor) -> Result<Self, capstone::Error> {
        let machine_arch = machine.arch();
        let machine_mode = machine.mode();
        let mut cs = Capstone::new_raw(machine_arch, machine_mode, NO_EXTRA_MODE, None)?;
        cs.set_detail(true)?;

        Ok(InstructionDecoder { machine, cs })
    }
}

pub trait InstructionVisitorError: error::Error {}

// libopcodes translation
// jsr => CS_GROUP_CALL
// branch => ?? only sparc rett

/// A callback trait that is invoked whenever an [InstructionDecoder] processes a new instruction.
pub trait InstructionVisitor<E: InstructionVisitorError> {
    /// Called when decoding begins with the type of [machine] that instructions are being decoded for,
    /// and the virtual address of the first instruction being decoded.
    fn visit_begin(&mut self, machine: MachineDescriptor, addr: usize) -> Result<(), E>;

    /// Called after the last instruction has been decoded with the virtual address of the final byte of decoded data.
    fn visit_end(&mut self, addr: usize) -> Result<(), E>;

    /// Visit the [instruction] from the given [arch] and [mode].
    fn visit_instruction(&mut self, instruction: &Insn, detail: InsnDetail) -> Result<(), E>;
}

impl<'s> InstructionDecoder<'s> {
    /// Decode a block of instructions given by [data], treating the virtual address
    /// of the first instruction as [base_address] and notify the instruction [visitor].
    pub fn decode<V, E>(
        &mut self,
        base_address: usize,
        data: &[u8],
        visitor: &mut V,
    ) -> Result<(), InstructionDecoderError<E>>
        where
            V: InstructionVisitor<E>,
            E: InstructionVisitorError,
    {
        let instructions = self.cs.disasm_all(data, base_address as u64)?;
        let mut last_address = base_address;

        visitor.visit_begin(self.machine, base_address)?;

        for instruction in instructions.iter() {
            last_address = instruction.address() as usize;
            let detail = self.cs.insn_detail(&instruction)?;

            visitor.visit_instruction(&instruction, detail)?;
        }

        visitor.visit_end(last_address)?;

        Ok(())
    }
}
