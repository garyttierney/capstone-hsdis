use arch::MachineDescriptor;
use capstone::prelude::Capstone;
use capstone::{Error, Insn, InsnDetail, NO_EXTRA_MODE};

/// A decoder that can disassemble machine code for a given [MachineDescriptor].
pub struct InstructionDecoder {
    /// A descriptor of the machine disassembly is being generated for.
    machine: MachineDescriptor,
}

impl InstructionDecoder {
    /// Create a new [InstructionDecoder] that decodes instructions for the
    /// given [machine].
    fn new(machine: MachineDescriptor) -> Self {
        InstructionDecoder { machine }
    }
}

// libopcodes translation
// jsr => CS_GROUP_CALL
// branch => ?? only sparc rett

/// A callback trait that is invoked whenever an [InstructionDecoder] processes a new instruction.
pub trait InstructionVisitor {
    /// Called when decoding begins with the type of [machine] that instructions are being decoded for,
    /// and the virtual address of the first instruction being decoded.
    fn visit_begin(&mut self, machine: MachineDescriptor, addr: u64);

    /// Called after the last instruction has been decoded with the virtual address of the final byte of decoded data.
    fn visit_end(&mut self, addr: u64);

    /// Visit the [instruction] from the given [arch] and [mode].
    fn visit_instruction(&mut self, instruction: &Insn, detail: InsnDetail);
}

impl InstructionDecoder {
    /// Decode a block of instructions given by [data], treating the virtual address
    /// of the first instruction as [base_address] and notify the instruction [visitor].
    pub fn decode<V>(&self, base_address: u64, data: &[u8], visitor: &mut V) -> Result<(), Error>
    where
        V: InstructionVisitor,
    {
        let machine_arch = self.machine.arch();
        let machine_mode = self.machine.mode();
        let mut cs = Capstone::new_raw(machine_arch, machine_mode, NO_EXTRA_MODE, None)?;

        cs.set_detail(true)?;

        let instructions = cs.disasm_all(data, base_address as u64)?;
        let mut last_address = base_address;

        visitor.visit_begin(self.machine, base_address);

        for instruction in instructions.iter() {
            visitor.visit_instruction(&instruction, cs.insn_detail(&instruction)?);
            last_address = instruction.address();
        }

        visitor.visit_end(last_address);

        Ok(())
    }
}

/// Default [InstructionDecoder] that operates on machine code from the host architecture.
impl Default for InstructionDecoder {
    fn default() -> Self {
        InstructionDecoder::new(MachineDescriptor::default())
    }
}
