/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015-2018 - ARM Ltd
 * Author: David Brazdil <marc.zyngier@arm.com>
 */

#include <linux/linkage.h>
#include <linux/init.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/pgtable.h>

#include <asm/alternative.h>
#include <asm/assembler.h>
#include <asm/cpufeature.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>
#include <asm/mmu.h>

	.text
	.pushsection	.idmap.text, "ax"

/*
 * Initialize EL2 CPU state when a core is booted.
 * Only uses registers x0 .. x3.
 */
SYM_FUNC_START(hyp_setup)
#ifdef __KVM_NVHE_HYPERVISOR__
	mov_q	x0, HCR_HOST_NVHE_FLAGS
#else
	mov_q	x0, HCR_HOST_VHE_FLAGS
#endif
	msr	hcr_el2, x0
	isb

	/*
	 * Allow Non-secure EL1 and EL0 to access physical timer and counter.
	 * This is not necessary for VHE, since the host kernel runs in EL2,
	 * and EL0 accesses are configured in the later stage of boot process.
	 * Note that when HCR_EL2.E2H == 1, CNTHCTL_EL2 has the same bit layout
	 * as CNTKCTL_EL1, and CNTKCTL_EL1 accessing instructions are redefined
	 * to access CNTHCTL_EL2. This allows the kernel designed to run at EL1
	 * to transparently mess with the EL0 bits via CNTKCTL_EL1 access in
	 * EL2.
	 */
#ifdef __KVM_NVHE_HYPERVISOR__
	mrs	x0, cnthctl_el2
	orr	x0, x0, #3			// Enable EL1 physical timers
	msr	cnthctl_el2, x0
#endif
	msr	cntvoff_el2, xzr		// Clear virtual offset

#ifdef CONFIG_ARM_GIC_V3
	/* GICv3 system register access */
	mrs	x0, id_aa64pfr0_el1
	ubfx	x0, x0, #ID_AA64PFR0_GIC_SHIFT, #4
	cbz	x0, 3f

	mrs_s	x0, SYS_ICC_SRE_EL2
	orr	x0, x0, #ICC_SRE_EL2_SRE	// Set ICC_SRE_EL2.SRE==1
	orr	x0, x0, #ICC_SRE_EL2_ENABLE	// Set ICC_SRE_EL2.Enable==1
	msr_s	SYS_ICC_SRE_EL2, x0
	isb					// Make sure SRE is now set
	mrs_s	x0, SYS_ICC_SRE_EL2		// Read SRE back,
	tbz	x0, #0, 3f			// and check that it sticks
	msr_s	SYS_ICH_HCR_EL2, xzr		// Reset ICC_HCR_EL2 to defaults

3:
#endif

	/* Populate ID registers. */
	mrs	x0, midr_el1
	mrs	x1, mpidr_el1
	msr	vpidr_el2, x0
	msr	vmpidr_el2, x1

#ifdef CONFIG_COMPAT
	msr	hstr_el2, xzr			// Disable CP15 traps to EL2
#endif

	/* EL2 debug */
	mrs	x1, id_aa64dfr0_el1
	sbfx	x0, x1, #ID_AA64DFR0_PMUVER_SHIFT, #4
	cmp	x0, #1
	b.lt	4f				// Skip if no PMU present
	mrs	x0, pmcr_el0			// Disable debug access traps
	ubfx	x0, x0, #11, #5			// to EL2 and allow access to
4:
	csel	x3, xzr, x0, lt			// all PMU counters from EL1

	/* Statistical profiling */
	ubfx	x0, x1, #ID_AA64DFR0_PMSVER_SHIFT, #4
	cbz	x0, 6f				// Skip if SPE not present
#ifdef __KVM_NVHE_HYPERVISOR__
	mrs_s	x2, SYS_PMBIDR_EL1		// If SPE available at EL2,
	and	x2, x2, #(1 << SYS_PMBIDR_EL1_P_SHIFT)
	cbnz	x2, 5f				// then permit sampling of physical
	mov	x2, #(1 << SYS_PMSCR_EL2_PCT_SHIFT | \
		      1 << SYS_PMSCR_EL2_PA_SHIFT)
	msr_s	SYS_PMSCR_EL2, x2		// addresses and physical counter
5:
	mov	x1, #(MDCR_EL2_E2PB_MASK << MDCR_EL2_E2PB_SHIFT)
	orr	x3, x3, x1			// If we don't have VHE, then
#else
	orr	x3, x3, #MDCR_EL2_TPMS		// For VHE, use EL2 translation
						// and disable access from EL1
#endif
6:	msr	mdcr_el2, x3			// Configure debug traps

	/* LORegions */
	mrs	x1, id_aa64mmfr1_el1
	ubfx	x0, x1, #ID_AA64MMFR1_LOR_SHIFT, 4
	cbz	x0, 1f
	msr_s	SYS_LORC_EL1, xzr
1:

	/* Stage-2 translation */
	msr	vttbr_el2, xzr

#ifdef __KVM_NVHE_HYPERVISOR__
	/*
	 * When VHE is not in use, early init of EL2 and EL1 needs to be
	 * done here.
	 * When VHE _is_ in use, EL1 will not be used in the host and
	 * requires no configuration, and all non-hyp-specific EL2 setup
	 * will be done via the _EL1 system register aliases in __cpu_setup.
	 */
	mov_q	x0, (SCTLR_EL1_RES1 | ENDIAN_SET_EL1)
	msr	sctlr_el1, x0

	/* Coprocessor traps. */
	mov	x0, #0x33ff
	msr	cptr_el2, x0			// Disable copro. traps to EL2

	/* SVE register access */
	mrs	x1, id_aa64pfr0_el1
	ubfx	x1, x1, #ID_AA64PFR0_SVE_SHIFT, #4
	cbz	x1, 7f

	bic	x0, x0, #CPTR_EL2_TZ		// Also disable SVE traps
	msr	cptr_el2, x0			// Disable copro. traps to EL2
	isb
	mov	x1, #ZCR_ELx_LEN_MASK		// SVE: Enable full vector
	msr_s	SYS_ZCR_EL2, x1			// length for EL1.

	/* spsr */
7:	mov	x0, #(PSR_F_BIT | PSR_I_BIT | PSR_A_BIT | PSR_D_BIT |\
		      PSR_MODE_EL1h)
	msr	spsr_el2, x0
#endif
	ret
SYM_FUNC_END(hyp_setup)
