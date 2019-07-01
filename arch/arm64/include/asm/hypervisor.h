/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_HYPERVISOR_H
#define _ASM_ARM64_HYPERVISOR_H

#include <linux/arm-smccc.h>
#include <asm/xen/hypervisor.h>

static inline bool kvm_arm_hyp_service_available(u32 func_id)
{
	extern DECLARE_BITMAP(__kvm_arm_hyp_services, ARM_SMCCC_KVM_NUM_FUNCS);

	if (func_id >= ARM_SMCCC_KVM_NUM_FUNCS)
		return -EINVAL;

	return test_bit(func_id, __kvm_arm_hyp_services);
}

#endif
