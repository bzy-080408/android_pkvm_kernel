/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#ifndef __ARM_KVM_ASM_H__
#define __ARM_KVM_ASM_H__

#include <asm/virt.h>

#define	VCPU_WORKAROUND_2_FLAG_SHIFT	0
#define	VCPU_WORKAROUND_2_FLAG		(_AC(1, UL) << VCPU_WORKAROUND_2_FLAG_SHIFT)

#define ARM_EXIT_WITH_SERROR_BIT  31
#define ARM_EXCEPTION_CODE(x)	  ((x) & ~(1U << ARM_EXIT_WITH_SERROR_BIT))
#define ARM_EXCEPTION_IS_TRAP(x)  (ARM_EXCEPTION_CODE((x)) == ARM_EXCEPTION_TRAP)
#define ARM_SERROR_PENDING(x)	  !!((x) & (1U << ARM_EXIT_WITH_SERROR_BIT))

#define ARM_EXCEPTION_IRQ	  0
#define ARM_EXCEPTION_EL1_SERROR  1
#define ARM_EXCEPTION_TRAP	  2
#define ARM_EXCEPTION_IL	  3
/* The hyp-stub will return this for any kvm_call_hyp() call */
#define ARM_EXCEPTION_HYP_GONE	  HVC_STUB_ERR

#define kvm_arm_exception_type					\
	{ARM_EXCEPTION_IRQ,		"IRQ"		},	\
	{ARM_EXCEPTION_EL1_SERROR, 	"SERROR"	},	\
	{ARM_EXCEPTION_TRAP, 		"TRAP"		},	\
	{ARM_EXCEPTION_HYP_GONE,	"HYP_GONE"	}

/*
 * Size of the HYP vectors preamble. kvm_patch_vector_branch() generates code
 * that jumps over this.
 */
#define KVM_VECTOR_PREAMBLE	(2 * AARCH64_INSN_SIZE)

#define __SMCCC_WORKAROUND_1_SMC_SZ 36

#ifndef __ASSEMBLY__

#include <linux/mm.h>

/*
 * Translate name of a symbol defined in VHE/nVHE hyp implementations
 * to the name seen by kernel proper. All nVHE symbols are prefixed by
 * the build system to avoid clashes with the VHE variants.
 */
#define __kvm_vhe_sym(sym)	sym
#define __kvm_nvhe_sym(sym)	__kvm_nvhe_##sym

#define DECLARE_KVM_VHE_SYM(sym)	extern char __kvm_vhe_sym(sym)[]
#define DECLARE_KVM_NVHE_SYM(sym)	extern char __kvm_nvhe_sym(sym)[]

/*
 * Define a pair of symbols sharing the same name but one defined in
 * VHE and the other in nVHE hyp implementations.
 */
#define DECLARE_KVM_HYP_SYM(sym)		\
	DECLARE_KVM_VHE_SYM(sym);		\
	DECLARE_KVM_NVHE_SYM(sym)

/* Translate a kernel address of @sym into its equivalent linear mapping */
#define kvm_ksym_ref(sym)						\
	({								\
		void *val = &sym;					\
		if (!is_kernel_in_hyp_mode())				\
			val = lm_alias(&sym);				\
		val;							\
	 })
#define kvm_ksym_ref_vhe(sym)	kvm_ksym_ref(__kvm_vhe_sym(sym))
#define kvm_ksym_ref_nvhe(sym)	kvm_ksym_ref(__kvm_nvhe_sym(sym))

struct kvm;
struct kvm_vcpu;

DECLARE_KVM_NVHE_SYM(__kvm_hyp_init);
DECLARE_KVM_NVHE_SYM(__kvm_hyp_init_end);

DECLARE_KVM_HYP_SYM(__kvm_hyp_vector);

#ifdef CONFIG_KVM_INDIRECT_VECTORS
DECLARE_KVM_HYP_SYM(__bp_harden_hyp_vecs);
extern atomic_t arm64_el2_vector_last_slot;
#endif

extern void __kvm_flush_vm_context(void);
extern void __kvm_tlb_flush_vmid_ipa(struct kvm *kvm, phys_addr_t ipa);
extern void __kvm_tlb_flush_vmid(struct kvm *kvm);
extern void __kvm_tlb_flush_local_vmid(struct kvm_vcpu *vcpu);

extern void __kvm_timer_set_cntvoff(u64 cntvoff);

extern int __kvm_vcpu_run(struct kvm_vcpu *vcpu);

extern void __kvm_set_ssbd_callback_required(void);
extern void __kvm_enable_ssbs(void);

extern u64 __vgic_v3_get_ich_vtr_el2(void);
extern u64 __vgic_v3_read_vmcr(void);
extern void __vgic_v3_write_vmcr(u32 vmcr);
extern void __vgic_v3_init_lrs(void);

extern u32 __kvm_get_mdcr_el2(void);

extern char __smccc_workaround_1_smc[__SMCCC_WORKAROUND_1_SMC_SZ];

/*
 * Obtain the PC-relative address of a kernel symbol
 * s: symbol
 *
 * The goal of this macro is to return a symbol's address based on a
 * PC-relative computation, as opposed to a loading the VA from a
 * constant pool or something similar. This works well for HYP, as an
 * absolute VA is guaranteed to be wrong. Only use this if trying to
 * obtain the address of a symbol (i.e. not something you obtained by
 * following a pointer).
 */
#define hyp_symbol_addr(s)						\
	({								\
		typeof(s) *addr;					\
		asm("adrp	%0, %1\n"				\
		    "add	%0, %0, :lo12:%1\n"			\
		    : "=r" (addr) : "S" (&s));				\
		addr;							\
	})

#else /* __ASSEMBLY__ */

.macro get_host_ctxt reg, tmp
	adr_this_cpu \reg, kvm_host_data, \tmp
	add	\reg, \reg, #HOST_DATA_CONTEXT
.endm

.macro get_vcpu_ptr vcpu, ctxt
	get_host_ctxt \ctxt, \vcpu
	ldr	\vcpu, [\ctxt, #HOST_CONTEXT_VCPU]
	kern_hyp_va	\vcpu
.endm

#define CPU_GP_REG_OFFSET(x)	(CPU_GP_REGS + x)
#define CPU_XREG_OFFSET(x)	CPU_GP_REG_OFFSET(CPU_USER_PT_REGS + 8*x)
#define CPU_SP_EL0_OFFSET	(CPU_XREG_OFFSET(30) + 8)

/*
 * We treat x18 as callee-saved as the host may use it as a platform
 * register (e.g. for shadow call stack).
 */
.macro save_callee_saved_regs ctxt
	str	x18,      [\ctxt, #CPU_XREG_OFFSET(18)]
	stp	x19, x20, [\ctxt, #CPU_XREG_OFFSET(19)]
	stp	x21, x22, [\ctxt, #CPU_XREG_OFFSET(21)]
	stp	x23, x24, [\ctxt, #CPU_XREG_OFFSET(23)]
	stp	x25, x26, [\ctxt, #CPU_XREG_OFFSET(25)]
	stp	x27, x28, [\ctxt, #CPU_XREG_OFFSET(27)]
	stp	x29, lr,  [\ctxt, #CPU_XREG_OFFSET(29)]
.endm

.macro restore_callee_saved_regs ctxt
	// We require \ctxt is not x18-x28
	ldr	x18,      [\ctxt, #CPU_XREG_OFFSET(18)]
	ldp	x19, x20, [\ctxt, #CPU_XREG_OFFSET(19)]
	ldp	x21, x22, [\ctxt, #CPU_XREG_OFFSET(21)]
	ldp	x23, x24, [\ctxt, #CPU_XREG_OFFSET(23)]
	ldp	x25, x26, [\ctxt, #CPU_XREG_OFFSET(25)]
	ldp	x27, x28, [\ctxt, #CPU_XREG_OFFSET(27)]
	ldp	x29, lr,  [\ctxt, #CPU_XREG_OFFSET(29)]
.endm

.macro save_sp_el0 ctxt, tmp
	mrs	\tmp,	sp_el0
	str	\tmp,	[\ctxt, #CPU_SP_EL0_OFFSET]
.endm

.macro restore_sp_el0 ctxt, tmp
	ldr	\tmp,	  [\ctxt, #CPU_SP_EL0_OFFSET]
	msr	sp_el0, \tmp
.endm

#endif

#endif /* __ARM_KVM_ASM_H__ */
