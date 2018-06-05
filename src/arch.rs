use super::capstone::{Arch, Mode};

pub fn current_arch() -> Option<(Arch, Mode)> {
    let machine_tuple = if cfg!(target_arch = "x86_64") {
        (Arch::X86, Mode::Mode64)
    } else if cfg!(target_arch = "x86") {
        (Arch::X86, Mode::Mode32)
    } else if cfg!(target_arch = "arm") {
        (Arch::ARM, Mode::Arm)
    } else {
        return None;
    };

    Some(machine_tuple)
}
