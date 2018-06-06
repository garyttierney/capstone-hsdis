use capstone::prelude::{ArchDetail, Capstone};
use capstone::{Arch, Insn, InsnDetail, Mode, NO_EXTRA_MODE};

use arch::MachineDescriptor;

pub struct InstructionDecoder {
    /// A descriptor of the machine disassembly is being generated for.
    machine: MachineDescriptor,
}

impl InstructionDecoder {
    fn new(machine: MachineDescriptor) -> Self {
        InstructionDecoder { machine }
    }
}

/// A callback trait that is invoked whenever an [InstructionDecoder] processes a new instruction.
pub trait InstructionVisitor {
    fn visit_begin(&mut self, machine: MachineDescriptor, addr: u64);

    fn visit_end(&mut self, addr: u64);

    /// Visit the [instruction] from the given [arch] and [mode].
    fn visit_insn(&mut self, instruction: &Insn, detail: &InsnDetail, arch: &ArchDetail);
}

impl InstructionDecoder {
    pub fn decode<V>(&self, base_address: u64, data: &[u8], visitor: &mut V)
    where
        V: InstructionVisitor,
    {
        let machine_name = self.machine.to_string();
        let machine_arch = self.machine.arch();
        let machine_mode = self.machine.mode();

        let mut cs =
            Capstone::new_raw(machine_arch, machine_mode, NO_EXTRA_MODE, None).expect("//@todo");

        cs.set_detail(true).expect("@todo");

        let instructions = cs.disasm_all(data, base_address as u64).expect("@todo");
        let mut last_address = base_address;

        visitor.visit_begin(self.machine, base_address);

        for insn in instructions.iter() {
            let insn_detail: InsnDetail = cs.insn_detail(&insn).unwrap();
            let arch_detail: ArchDetail = insn_detail.arch_detail();

            visitor.visit_insn(&insn, &insn_detail, &arch_detail);
            last_address = insn.address();
        }

        visitor.visit_end(last_address);
    }
}

/// Default [InstructionDecoder] that operates on machine code from the current architecture.
impl Default for InstructionDecoder {
    fn default() -> Self {
        InstructionDecoder::new(MachineDescriptor::default())
    }
}
