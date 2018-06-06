use super::capstone::{Arch, Mode};

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct MachineDescriptor(Arch, Mode);

impl MachineDescriptor {
    pub fn current() -> Option<Self> {
        let machine_tuple = if cfg!(target_arch = "x86_64") {
            MachineDescriptor(Arch::X86, Mode::Mode64)
        } else if cfg!(target_arch = "x86") {
            MachineDescriptor(Arch::X86, Mode::Mode32)
        } else if cfg!(target_arch = "arm") {
            MachineDescriptor(Arch::ARM, Mode::Arm)
        } else {
            return None;
        };

        Some(machine_tuple)
    }

    pub fn arch(&self) -> Arch {
        self.0
    }

    pub fn mode(&self) -> Mode {
        self.1
    }
}

impl ToString for MachineDescriptor {
    fn to_string(&self) -> String {
        let name = match (self.0, self.1) {
            (Arch::X86, Mode::Mode64) => "amd64",
            (Arch::X86, Mode::Mode32) => "i386",
            (Arch::ARM, Mode::Arm) => "arm",
            _ => "unknown",
        };

        name.to_owned()
    }
}

impl Default for MachineDescriptor {
    fn default() -> Self {
        MachineDescriptor::current().expect("Unable to determine current host machine")
    }
}
