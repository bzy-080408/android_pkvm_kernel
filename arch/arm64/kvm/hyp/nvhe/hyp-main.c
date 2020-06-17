// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>

#include <kvm/arm_hypercalls.h>

typedef unsigned long (*hypcall_fn_t)(unsigned long, unsigned long, unsigned long);

DEFINE_PER_CPU(struct kvm_nvhe_hyp_params, kvm_nvhe_hyp_params);
DEFINE_PER_CPU(struct kvm_vcpu, kvm_host_vcpu);

static void handle_host_hcall(struct kvm_vcpu *host_vcpu)
{
	unsigned long ret = 0;

	switch (smccc_get_function(host_vcpu)) {
	case KVM_HOST_SMCCC_FUNC(__kvm_flush_vm_context):
		__kvm_flush_vm_context();
		break;
	case KVM_HOST_SMCCC_FUNC(__kvm_tlb_flush_vmid_ipa): {
			struct kvm *kvm =
				(struct kvm *)smccc_get_arg1(host_vcpu);
			phys_addr_t ipa = smccc_get_arg2(host_vcpu);

			__kvm_tlb_flush_vmid_ipa(kvm, ipa);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__kvm_tlb_flush_vmid): {
			struct kvm *kvm =
				(struct kvm *)smccc_get_arg1(host_vcpu);

			__kvm_tlb_flush_vmid(kvm);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__kvm_tlb_flush_local_vmid): {
			struct kvm_vcpu *vcpu =
				(struct kvm_vcpu *)smccc_get_arg1(host_vcpu);

			__kvm_tlb_flush_local_vmid(vcpu);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__kvm_timer_set_cntvoff): {
			u64 cntvoff = smccc_get_arg1(host_vcpu);

			__kvm_timer_set_cntvoff(cntvoff);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__kvm_vcpu_run): {
			struct kvm_vcpu *vcpu =
				(struct kvm_vcpu *)smccc_get_arg1(host_vcpu);

			ret = __kvm_vcpu_run(vcpu);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_get_ich_vtr_el2):
		ret = __vgic_v3_get_ich_vtr_el2();
		break;
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_read_vmcr):
		ret = __vgic_v3_read_vmcr();
		break;
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_write_vmcr): {
			u32 vmcr = smccc_get_arg1(host_vcpu);

			__vgic_v3_write_vmcr(vmcr);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_init_lrs):
		__vgic_v3_init_lrs();
		break;
	case KVM_HOST_SMCCC_FUNC(__kvm_get_mdcr_el2):
		ret = __kvm_get_mdcr_el2();
		break;
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_save_aprs): {
			struct vgic_v3_cpu_if *cpu_if =
				(struct vgic_v3_cpu_if *)smccc_get_arg1(host_vcpu);

			__vgic_v3_save_aprs(cpu_if);
			break;
		}
	case KVM_HOST_SMCCC_FUNC(__vgic_v3_restore_aprs): {
			struct vgic_v3_cpu_if *cpu_if =
				(struct vgic_v3_cpu_if *)smccc_get_arg1(host_vcpu);

			__vgic_v3_restore_aprs(cpu_if);
			break;
		}
	default:
		/* Invalid host HVC. */
		smccc_set_retval(host_vcpu, SMCCC_RET_NOT_SUPPORTED, 0, 0, 0);
		return;
	}

	smccc_set_retval(host_vcpu, SMCCC_RET_SUCCESS, ret, 0, 0);
}

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

	/* Handle init params */
#ifdef CONFIG_ARM64_SSBD
	if (params->ssbd_callback_required)
		__this_cpu_write(arm64_ssbd_callback_required, 1);
#endif
	if (params->enable_ssbd)
		__kvm_enable_ssbs();

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

		if (exit_code == ARM_EXCEPTION_TRAP)
			handle_host_hcall(host_vcpu);
	}
}
