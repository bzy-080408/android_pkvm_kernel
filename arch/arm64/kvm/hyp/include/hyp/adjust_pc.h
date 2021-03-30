// SPDX-License-Identifier: GPL-2.0-only
/*
 * Guest PC manipulation helpers
 *
 * Copyright (C) 2012,2013 - ARM Ltd
 * Copyright (C) 2020 - Google LLC
 * Author: Marc Zyngier <maz@kernel.org>
 */

#ifndef __ARM64_KVM_HYP_ADJUST_PC_H__
#define __ARM64_KVM_HYP_ADJUST_PC_H__

#include <asm/kvm_emulate.h>
#include <asm/kvm_host.h>

void kvm_inject_exception(struct kvm_vcpu_arch_core *core_state);

static inline void kvm_skip_instr(struct kvm_vcpu_arch_core *core_state)
{
	if (vcpu_mode_is_32bit(core_state)) {
		kvm_skip_instr32(core_state);
	} else {
		*vcpu_pc(core_state) += 4;
		*vcpu_cpsr(core_state) &= ~PSR_BTYPE_MASK;
	}

	/* advance the singlestep state machine */
	*vcpu_cpsr(core_state) &= ~DBG_SPSR_SS;
}

/*
 * Skip an instruction which has been emulated at hyp while most guest sysregs
 * are live.
 */
static inline void __kvm_skip_instr(struct kvm_vcpu_arch_core *core_state)
{
	*vcpu_pc(core_state) = read_sysreg_el2(SYS_ELR);
	vcpu_gp_regs(core_state)->pstate = read_sysreg_el2(SYS_SPSR);

	kvm_skip_instr(core_state);

	write_sysreg_el2(vcpu_gp_regs(core_state)->pstate, SYS_SPSR);
	write_sysreg_el2(*vcpu_pc(core_state), SYS_ELR);
}

/*
 * Adjust the guest PC on entry, depending on flags provided by EL1
 * for the purpose of emulation (MMIO, sysreg) or exception injection.
 */
static inline void __adjust_pc(struct kvm_vcpu_arch_core *core_state)
{
	if (core_state->flags & KVM_ARM64_PENDING_EXCEPTION) {
		kvm_inject_exception(core_state);
		core_state->flags &= ~(KVM_ARM64_PENDING_EXCEPTION |
				      KVM_ARM64_EXCEPT_MASK);
	} else if (core_state->flags & KVM_ARM64_INCREMENT_PC) {
		kvm_skip_instr(core_state);
		core_state->flags &= ~KVM_ARM64_INCREMENT_PC;
	}
}

/*
 * Skip an instruction while host sysregs are live.
 * Assumes host is always 64-bit.
 */
static inline void kvm_skip_host_instr(void)
{
	write_sysreg_el2(read_sysreg_el2(SYS_ELR) + 4, SYS_ELR);
}

#endif
