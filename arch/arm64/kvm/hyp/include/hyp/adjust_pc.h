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

void kvm_inject_exception(struct kvm_vcpu *vcpu);

static inline void kvm_skip_instr(struct kvm_vcpu *vcpu)
{
	struct vcpu_hyp_state *vcpu_hyps = &hyp_state(vcpu);
	struct kvm_cpu_context *vcpu_ctxt = &vcpu_ctxt(vcpu);
	if (ctxt_mode_is_32bit(vcpu_ctxt)) {
		kvm_skip_instr32(vcpu);
	} else {
		*ctxt_pc(vcpu_ctxt) += 4;
		*ctxt_cpsr(vcpu_ctxt) &= ~PSR_BTYPE_MASK;
	}

	/* advance the singlestep state machine */
	*ctxt_cpsr(vcpu_ctxt) &= ~DBG_SPSR_SS;
}

/*
 * Skip an instruction which has been emulated at hyp while most guest sysregs
 * are live.
 */
static inline void __kvm_skip_instr(struct kvm_vcpu *vcpu)
{
	struct vcpu_hyp_state *vcpu_hyps = &hyp_state(vcpu);
	struct kvm_cpu_context *vcpu_ctxt = &vcpu_ctxt(vcpu);
	*ctxt_pc(vcpu_ctxt) = read_sysreg_el2(SYS_ELR);
	ctxt_gp_regs(vcpu_ctxt)->pstate = read_sysreg_el2(SYS_SPSR);

	kvm_skip_instr(vcpu);

	write_sysreg_el2(ctxt_gp_regs(vcpu_ctxt)->pstate, SYS_SPSR);
	write_sysreg_el2(*ctxt_pc(vcpu_ctxt), SYS_ELR);
}

/*
 * Adjust the guest PC on entry, depending on flags provided by EL1
 * for the purpose of emulation (MMIO, sysreg) or exception injection.
 */
static inline void __adjust_pc(struct kvm_vcpu *vcpu)
{
	struct vcpu_hyp_state *vcpu_hyps = &hyp_state(vcpu);
	struct kvm_cpu_context *vcpu_ctxt = &vcpu_ctxt(vcpu);
	if (hyp_state_flags(vcpu_hyps) & KVM_ARM64_PENDING_EXCEPTION) {
		kvm_inject_exception(vcpu);
		hyp_state_flags(vcpu_hyps) &= ~(KVM_ARM64_PENDING_EXCEPTION |
				      KVM_ARM64_EXCEPT_MASK);
	} else 	if (hyp_state_flags(vcpu_hyps) & KVM_ARM64_INCREMENT_PC) {
		kvm_skip_instr(vcpu);
		hyp_state_flags(vcpu_hyps) &= ~KVM_ARM64_INCREMENT_PC;
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
