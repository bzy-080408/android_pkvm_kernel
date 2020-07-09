// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: David Brazdil <dbrazdil@google.com>
 */

#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

#include <uapi/linux/psci.h>

int kvm_host_psci_call(struct kvm_vcpu *host_vcpu)
{
	return -EINVAL;
}
