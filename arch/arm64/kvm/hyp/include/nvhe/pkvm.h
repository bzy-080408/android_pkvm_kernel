/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

#ifndef __ARM64_KVM_NVHE_PKVM_H__
#define __ARM64_KVM_NVHE_PKVM_H__

struct shadow_entry {
	struct kvm_shadow_vm *vm;
	size_t size;
};

/* Maximum number of protected VMs that can be created. */
// TODO: This is an arbitrary number.
#define KVM_MAX_PVMS 256

/* Size of the shadow table. Must be a multiple of the page size. */
#define KVM_PVM_SHADOW_TABLE_SIZE \
	round_up(KVM_MAX_PVMS * sizeof(struct shadow_entry), PAGE_SIZE)

#define KVM_PVM_SHADOW_TABLE_PAGES \
	(KVM_PVM_SHADOW_TABLE_SIZE >> PAGE_SHIFT)

extern struct shadow_entry *shadow_table;

int __pkvm_init_shadow(const struct kvm *kvm, void *shadow_va, size_t size);

void __pkvm_teardown_shadow(const struct kvm *kvm);

struct kvm_vcpu_arch_core *hyp_get_shadow_core(const struct kvm_vcpu *vcpu);

#endif /* __ARM64_KVM_NVHE_PKVM_H__ */
