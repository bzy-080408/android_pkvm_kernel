// SPDX-License-Identifier: GPL-2.0

//! pKVM hyp module interfaces

use crate::error::{code::ENOMEM, Result};

/// Module ops structure passed to initialisation function at EL2.
pub type El2ModuleOps = *const bindings::pkvm_module_ops;

type El2InitFn = unsafe extern "C" fn(El2ModuleOps) -> core::ffi::c_int;

/// Load a hypervisor module at EL2.
pub fn load_el2_module(
	module: &'static crate::ThisModule,
	init_fn: El2InitFn,
	token: *mut u64,
) -> Result {

	unsafe {
		(*module.0).arch.hyp.init = Some(init_fn);
		let rc = bindings::__pkvm_load_el2_module(module.0, token);

		if rc != 0 {
			return Err(ENOMEM);
		}
	}

	Ok(())
}
