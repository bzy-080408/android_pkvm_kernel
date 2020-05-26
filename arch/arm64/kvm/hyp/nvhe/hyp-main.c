// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>

typedef unsigned long (*hypcall_fn_t)(unsigned long, unsigned long, unsigned long);

DEFINE_PER_CPU(struct kvm_nvhe_hyp_params, kvm_nvhe_hyp_params);
DEFINE_PER_CPU(struct kvm_vcpu, kvm_host_vcpu);

void __noreturn kvm_hyp_main(struct kvm_nvhe_hyp_params *params)
{
	/* Set tpidr_el2 for use by HYP */
	struct kvm_vcpu *host_vcpu;
	struct kvm_host_data *hyp_data;
	struct kvm_cpu_context *hyp_ctxt;
	int i;

	host_vcpu = this_cpu_ptr(&kvm_host_vcpu);
	hyp_data = this_cpu_ptr(&kvm_host_data);
	hyp_ctxt = &hyp_data->host_ctxt;

	/* Wipe the caller saved registers. */
	for (i = 0; i < 18; ++i)
		vcpu_gp_regs(host_vcpu)->regs.regs[i] = 0;

	__sysreg_save_state_nvhe(&host_vcpu->arch.ctxt);

	while (true) {
		u64 exit_code;

		/*
		 * Set the running cpu for the vectors to pass to __guest_exit
		 * so it can get the cpu context.
		 */
		hyp_ctxt->__hyp_running_vcpu = host_vcpu;

		/*
		 * Enter the host now that we feel like we're in charge.
		 *
		 * This should merge with __kvm_vcpu_run as host becomes more
		 * vcpu-like.
		 */
		exit_code = __guest_enter(host_vcpu, hyp_ctxt);

		/* TODO: handle exit codes properly */

		/*
		 * __kvm_call_hyp takes a pointer in the host address space and
		 * up to three arguments.
		 */
		if (exit_code == ARM_EXCEPTION_TRAP) {
			hypcall_fn_t func = (hypcall_fn_t)
				kern_hyp_va(vcpu_get_reg(host_vcpu, 0));
			unsigned long ret;

			ret = func(vcpu_get_reg(host_vcpu, 1),
				   vcpu_get_reg(host_vcpu, 2),
				   vcpu_get_reg(host_vcpu, 3));
			vcpu_set_reg(host_vcpu, 0, ret);
		}
	}
}
