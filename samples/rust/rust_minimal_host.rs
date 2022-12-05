// SPDX-License-Identifier: GPL-2.0

//! Rust minimal sample.

use kernel::prelude::*;
use kernel::pkvm;

use core::ptr;

module! {
    type: RustMinimal,
    name: b"rust_minimal",
    author: b"Rust for Linux Contributors",
    description: b"Rust minimal sample",
    license: b"GPL",
}

struct RustMinimal;

extern "C" {
	fn __kvm_nvhe_init(ops: pkvm::El2ModuleOps) -> core::ffi::c_int;
}

impl kernel::Module for RustMinimal {
    fn init(module: &'static ThisModule) -> Result<Self> {
	pkvm::load_el2_module(module, __kvm_nvhe_init, ptr::null_mut())?;
        Ok(RustMinimal)
    }
}
