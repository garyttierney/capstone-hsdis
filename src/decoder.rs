use arch::current_arch;
use capstone::*;
use capstone::{Arch, Insn, Mode};

pub struct InstructionDecoder {
    /// The supported capstone [Arch]itecture that the decoder is running on.
    arch: Arch,

    /// The architecture specific [Mode], e.g., 32-bit, 64-bit.
    mode: Mode,
}

impl InstructionDecoder {
    fn new(host: (Arch, Mode)) -> Self {
        InstructionDecoder {
            arch: host.0,
            mode: host.1
        }
    }
}

/// A callback trait that is invoked whenever an [InstructionDecoder] processes a new instruction.
pub trait InstructionVisitor {
    /// Visit the [instruction] from the given [arch] and [mode].
    fn visit(&mut self, instruction: &Insn, arch: Arch, mode: Mode);
}

impl InstructionDecoder {
    pub fn decode<V>(&self, data: &[u8], visitor: &mut V)
    where
        V: InstructionVisitor,
    {
        let mut capstone =
            Capstone::new_raw(self.arch, self.mode, NO_EXTRA_MODE, None).expect("//@todo");

        let insns = capstone.disasm_all(data, 0).expect("@todo");
        let iterator: InstructionIterator = insns.iter();

        for insn in iterator {
            visitor.visit(&insn, self.arch, self.mode);
        }
    }
}

/// Default [InstructionDecoder] that operates on machine code from the current architecture.
impl Default for InstructionDecoder {
    fn default() -> Self {
        InstructionDecoder::new(
            current_arch().expect("Unable to detect current architecture.  Fatal error"),
        )
    }
}
