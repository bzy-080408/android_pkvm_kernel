/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Linker script variables to be set after section resolution, as
 * ld.lld does not like variables assigned before SECTIONS is processed.
 */
#ifndef __ARM64_KERNEL_IMAGE_VARS_H
#define __ARM64_KERNEL_IMAGE_VARS_H

#ifndef LINKER_SCRIPT
#error This file should only be included in vmlinux.lds.S
#endif

#ifdef CONFIG_EFI

__efistub_kernel_size		= _edata - _text;
__efistub_primary_entry_offset	= primary_entry - _text;


/*
 * The EFI stub has its own symbol namespace prefixed by __efistub_, to
 * isolate it from the kernel proper. The following symbols are legally
 * accessed by the stub, so provide some aliases to make them accessible.
 * Only include data symbols here, or text symbols of functions that are
 * guaranteed to be safe when executed at another offset than they were
 * linked at. The routines below are all implemented in assembler in a
 * position independent manner
 */
__efistub_memcmp		= __pi_memcmp;
__efistub_memchr		= __pi_memchr;
__efistub_memcpy		= __pi_memcpy;
__efistub_memmove		= __pi_memmove;
__efistub_memset		= __pi_memset;
__efistub_strlen		= __pi_strlen;
__efistub_strnlen		= __pi_strnlen;
__efistub_strcmp		= __pi_strcmp;
__efistub_strncmp		= __pi_strncmp;
__efistub_strrchr		= __pi_strrchr;
__efistub___clean_dcache_area_poc = __pi___clean_dcache_area_poc;

#ifdef CONFIG_KASAN
__efistub___memcpy		= __pi_memcpy;
__efistub___memmove		= __pi_memmove;
__efistub___memset		= __pi_memset;
#endif

__efistub__text			= _text;
__efistub__end			= _end;
__efistub__edata		= _edata;
__efistub_screen_info		= screen_info;
__efistub__ctype		= _ctype;

#endif

#ifdef CONFIG_KVM

/*
 * KVM nVHE code has its own symbol namespace prefixed by __kvm_nvhe_, to
 * isolate it from the kernel proper. The following symbols are legally
 * accessed by it, therefore provide aliases to make them linkable.
 * Do not include symbols which may not be safely accessed under hypervisor
 * memory mappings.
 */

__kvm_nvhe___debug_switch_to_guest = __debug_switch_to_guest;
__kvm_nvhe___debug_switch_to_host = __debug_switch_to_host;
__kvm_nvhe___fpsimd_restore_state = __fpsimd_restore_state;
__kvm_nvhe___fpsimd_save_state = __fpsimd_save_state;
__kvm_nvhe___guest_enter = __guest_enter;
__kvm_nvhe___guest_exit = __guest_exit;
__kvm_nvhe___hyp_panic_string = __hyp_panic_string;
__kvm_nvhe___hyp_stub_vectors = __hyp_stub_vectors;
__kvm_nvhe___icache_flags = __icache_flags;
__kvm_nvhe___kvm_enable_ssbs = __kvm_enable_ssbs;
__kvm_nvhe___kvm_get_mdcr_el2 = __kvm_get_mdcr_el2;
__kvm_nvhe___kvm_timer_set_cntvoff = __kvm_timer_set_cntvoff;
__kvm_nvhe___sysreg32_restore_state = __sysreg32_restore_state;
__kvm_nvhe___sysreg32_save_state = __sysreg32_save_state;
__kvm_nvhe___sysreg_restore_state_nvhe = __sysreg_restore_state_nvhe;
__kvm_nvhe___sysreg_save_state_nvhe = __sysreg_save_state_nvhe;
__kvm_nvhe___timer_disable_traps = __timer_disable_traps;
__kvm_nvhe___timer_enable_traps = __timer_enable_traps;
__kvm_nvhe___vgic_v2_perform_cpuif_access = __vgic_v2_perform_cpuif_access;
__kvm_nvhe___vgic_v3_activate_traps = __vgic_v3_activate_traps;
__kvm_nvhe___vgic_v3_deactivate_traps = __vgic_v3_deactivate_traps;
__kvm_nvhe___vgic_v3_get_ich_vtr_el2 = __vgic_v3_get_ich_vtr_el2;
__kvm_nvhe___vgic_v3_init_lrs = __vgic_v3_init_lrs;
__kvm_nvhe___vgic_v3_perform_cpuif_access = __vgic_v3_perform_cpuif_access;
__kvm_nvhe___vgic_v3_read_vmcr = __vgic_v3_read_vmcr;
__kvm_nvhe___vgic_v3_restore_aprs = __vgic_v3_restore_aprs;
__kvm_nvhe___vgic_v3_restore_state = __vgic_v3_restore_state;
__kvm_nvhe___vgic_v3_save_aprs = __vgic_v3_save_aprs;
__kvm_nvhe___vgic_v3_save_state = __vgic_v3_save_state;
__kvm_nvhe___vgic_v3_write_vmcr = __vgic_v3_write_vmcr;
__kvm_nvhe_abort_guest_exit_end = abort_guest_exit_end;
__kvm_nvhe_abort_guest_exit_start = abort_guest_exit_start;
__kvm_nvhe_arm64_const_caps_ready = arm64_const_caps_ready;
__kvm_nvhe_arm64_enable_wa2_handling = arm64_enable_wa2_handling;
__kvm_nvhe_arm64_ssbd_callback_required = arm64_ssbd_callback_required;
__kvm_nvhe_cpu_hwcap_keys = cpu_hwcap_keys;
__kvm_nvhe_cpu_hwcaps = cpu_hwcaps;
#ifdef CONFIG_ARM64_PSEUDO_NMI
__kvm_nvhe_gic_pmr_sync = gic_pmr_sync;
#endif
__kvm_nvhe_hyp_panic = hyp_panic;
__kvm_nvhe_idmap_t0sz = idmap_t0sz;
__kvm_nvhe_kimage_voffset = kimage_voffset;
__kvm_nvhe_kvm_host_data = kvm_host_data;
__kvm_nvhe_kvm_patch_vector_branch = kvm_patch_vector_branch;
__kvm_nvhe_kvm_skip_instr32 = kvm_skip_instr32;
__kvm_nvhe_kvm_update_va_mask = kvm_update_va_mask;
__kvm_nvhe_kvm_vgic_global_state = kvm_vgic_global_state;
__kvm_nvhe_panic = panic;
#ifdef CONFIG_ARM64_SVE
__kvm_nvhe_sve_load_state = sve_load_state;
__kvm_nvhe_sve_save_state = sve_save_state;
#endif
__kvm_nvhe_vgic_v2_cpuif_trap = vgic_v2_cpuif_trap;
__kvm_nvhe_vgic_v3_cpuif_trap = vgic_v3_cpuif_trap;

#endif /* CONFIG_KVM */

#endif /* __ARM64_KERNEL_IMAGE_VARS_H */
