// SPDX-License-Identifier: GPL-2.0

//! Simple EL2 module written in rust. This is the hyp part.

/// EL2 initialisation function called by the hypervisor.
#[no_mangle]
pub extern "C" fn init(ops: kernel::pkvm::El2ModuleOps) -> core::ffi::c_int {
	let msg = b"oh no, EL2 is rusting away!\n\0";

	unsafe {
		let puts = (*ops).puts;

		match puts {
			Some(func) => func(msg.as_ptr() as _),
			None => (),
		}
	}
	0
}
