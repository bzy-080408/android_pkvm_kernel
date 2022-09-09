/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

#ifndef __ARM64_KVM_NVHE_PKVM_H__
#define __ARM64_KVM_NVHE_PKVM_H__

#include <asm/kvm_pkvm.h>

#include <nvhe/gfp.h>
#include <nvhe/spinlock.h>

/*
 * Holds the relevant data for maintaining the vcpu state completely at hyp.
 */
struct kvm_shadow_vcpu_state {
	struct kvm_vcpu shadow_vcpu;
	struct kvm_vcpu *host_vcpu;
	struct kvm_shadow_vm *shadow_vm;
};

/*
 * Holds the relevant data for running a protected vm.
 */
struct kvm_shadow_vm {
	struct kvm kvm;
	struct kvm *host_kvm;
	size_t shadow_area_size;

	/*
	 * The number of vcpus initialized and ready to run in the shadow vm.
	 * Modifying this is protected by shadow_lock.
	 */
	unsigned int nr_vcpus;

	struct kvm_pgtable pgt;
	struct kvm_pgtable_mm_ops mm_ops;
	struct hyp_pool pool;
	hyp_spinlock_t lock;

	/* Array containing the shadow state for each vcpu. */
	struct kvm_shadow_vcpu_state shadow_vcpu_states[0];
};

static inline struct kvm_shadow_vcpu_state *get_shadow_state(struct kvm_vcpu *shadow_vcpu)
{
	return container_of(shadow_vcpu, struct kvm_shadow_vcpu_state, shadow_vcpu);
}

static inline struct kvm_shadow_vm *get_shadow_vm(struct kvm_vcpu *shadow_vcpu)
{
	return get_shadow_state(shadow_vcpu)->shadow_vm;
}

void hyp_shadow_table_init(void *tbl);
int __pkvm_init_shadow(struct kvm *kvm, unsigned long shadow_hva,
		       size_t shadow_size, unsigned long pgd_hva);
int __pkvm_init_shadow_vcpu(unsigned int shadow_handle,
			    struct kvm_vcpu *host_vcpu);
int __pkvm_teardown_shadow(unsigned int shadow_handle);

struct kvm_shadow_vcpu_state *
pkvm_load_shadow_vcpu_state(unsigned int shadow_handle, unsigned int vcpu_idx);
void pkvm_put_shadow_vcpu_state(struct kvm_shadow_vcpu_state *shadow_state);

#endif /* __ARM64_KVM_NVHE_PKVM_H__ */
