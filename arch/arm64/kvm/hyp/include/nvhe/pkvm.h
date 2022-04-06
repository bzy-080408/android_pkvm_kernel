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
	/* The data for the shadow vcpu. */
	struct kvm_vcpu shadow_vcpu;

	/* A pointer to the host's vcpu. */
	struct kvm_vcpu *host_vcpu;

	/* A pointer to the shadow vm. */
	struct kvm_shadow_vm *shadow_vm;
};

/*
 * Holds the relevant data for running a protected vm.
 */
struct kvm_shadow_vm {
	/* The data for the shadow kvm. */
	struct kvm kvm;

	/* The host's kvm structure. */
	struct kvm *host_kvm;

	/* The total size of the donated shadow area. */
	size_t shadow_area_size;

	struct kvm_pgtable pgt;
	struct kvm_pgtable_mm_ops mm_ops;
	struct hyp_pool pool;
	hyp_spinlock_t lock;

	/* Array of the shadow state per vcpu. */
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
int __pkvm_init_shadow(struct kvm *kvm, void *shadow_va, size_t size, void *pgd);
int __pkvm_teardown_shadow(unsigned int shadow_handle);

#endif /* __ARM64_KVM_NVHE_PKVM_H__ */

