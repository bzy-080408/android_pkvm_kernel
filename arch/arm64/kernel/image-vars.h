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

/* If nVHE code panics, it ERETs into panic() in EL1. */
__kvm_nvhe___hyp_panic_string		= __hyp_panic_string;
__kvm_nvhe_panic			= panic;

/* Values used by the hyp-init vector. */
__kvm_nvhe___hyp_stub_vectors		= __hyp_stub_vectors;
__kvm_nvhe_idmap_t0sz			= idmap_t0sz;

/* Alternative callbacks, referenced in .altinstructions. Executed in EL1. */
__kvm_nvhe_arm64_enable_wa2_handling	= arm64_enable_wa2_handling;
__kvm_nvhe_kvm_patch_vector_branch	= kvm_patch_vector_branch;
__kvm_nvhe_kvm_update_va_mask		= kvm_update_va_mask;

/* Values used to convert between memory mappings, read-only after init. */
__kvm_nvhe_kimage_voffset		= kimage_voffset;

/* Data shared with the kernel. */
__kvm_nvhe_cpu_hwcaps			= cpu_hwcaps;
__kvm_nvhe_cpu_hwcap_keys		= cpu_hwcap_keys;
__kvm_nvhe___icache_flags		= __icache_flags;
__kvm_nvhe_kvm_vgic_global_state	= kvm_vgic_global_state;
__kvm_nvhe___kvm_bp_vect_base		= __kvm_bp_vect_base;

/* Static keys shared with the kernel. */
__kvm_nvhe_arm64_const_caps_ready	= arm64_const_caps_ready;
#ifdef CONFIG_ARM64_PSEUDO_NMI
__kvm_nvhe_gic_pmr_sync			= gic_pmr_sync;
#endif
__kvm_nvhe_vgic_v2_cpuif_trap		= vgic_v2_cpuif_trap;
__kvm_nvhe_vgic_v3_cpuif_trap		= vgic_v3_cpuif_trap;

/* SVE support, currently unused by nVHE. */
#ifdef CONFIG_ARM64_SVE
__kvm_nvhe_sve_save_state		= sve_save_state;
__kvm_nvhe_sve_load_state		= sve_load_state;
#endif

/* Position-independent library routines */
__kvm_nvhe_clear_page			= __kvm_nvhe___pi_clear_page;
__kvm_nvhe_copy_page			= __kvm_nvhe___pi_copy_page;
__kvm_nvhe_memcpy			= __kvm_nvhe___pi_memcpy;
__kvm_nvhe_memset			= __kvm_nvhe___pi_memset;

#ifdef CONFIG_KASAN
__kvm_nvhe___memcpy			= __kvm_nvhe___pi_memcpy;
__kvm_nvhe___memset			= __kvm_nvhe___pi_memset;
#endif

/* Kernel memory sections */
__kvm_nvhe___start_rodata		= __start_rodata;
__kvm_nvhe___end_rodata			= __end_rodata;
__kvm_nvhe___bss_start			= __bss_start;
__kvm_nvhe___bss_stop			= __bss_stop;

/* Hyp memory sections */
__kvm_nvhe___hyp_idmap_text_start	= __hyp_idmap_text_start;
__kvm_nvhe___hyp_idmap_text_end		= __hyp_idmap_text_end;
__kvm_nvhe___hyp_text_start		= __hyp_text_start;
__kvm_nvhe___hyp_text_end		= __hyp_text_end;
__kvm_nvhe___hyp_bss_start		= __hyp_bss_start;
__kvm_nvhe___hyp_bss_end		= __hyp_bss_end;

#endif /* CONFIG_KVM */

#endif /* __ARM64_KERNEL_IMAGE_VARS_H */
