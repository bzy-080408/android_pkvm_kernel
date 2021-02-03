/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

#ifndef __ARM64_KVM_NVHE_PKVM_H__
#define __ARM64_KVM_NVHE_PKVM_H__

/*
 * To track memory allocated for the shadow area (per VM).
 */
struct shadow_memory_area {
	void *shadow_addr;
	int num_vcpus;
	size_t shadow_size;
};

/*
 * A container for the vcpu state that hyp needs to maintain for protected VMs.
 */
struct shadow_vcpu_state {
	struct kvm_shadow_vm *vm;
	struct kvm_vcpu vcpu;
};

/*
 * The offset of the shadow vm state within the shadow area.
 * It's located at the beginning of the shadow area.
 */
#define SHADOW_VM_OFFSET 0ULL

/*
 * The offset of the shadow vcpu state within the shadow area.
 * They are located after the shadow vm.
 */
#define SHADOW_VCPUS_OFFSET sizeof(struct kvm_shadow_vm)

/* Maximum number of protected VMs that can be created. */
// TODO: This is an arbitrary number for now. Consider how to dynamically
// allocated based on memory donated from the host.
#define KVM_MAX_PVMS 256

/* Size of the shadow table. Must be a multiple of the page size. */
#define KVM_PVM_SHADOW_TABLE_SIZE \
	round_up(KVM_MAX_PVMS * sizeof(struct shadow_memory_area), PAGE_SIZE)

#define KVM_PVM_SHADOW_TABLE_PAGES \
	(KVM_PVM_SHADOW_TABLE_SIZE >> PAGE_SHIFT)

extern struct shadow_memory_area *shadow_table;

int __pkvm_init_shadow(struct kvm *kvm, void *shadow_va, size_t size);

void __pkvm_teardown_shadow(struct kvm *kvm);

struct kvm_vcpu *hyp_get_shadow_vcpu(const struct kvm_vcpu *host_vcpu);

static inline size_t hyp_get_shadow_size(int num_vcpus)
{
	/* shadow space for the vm struct and its vcpu states */
	return SHADOW_VCPUS_OFFSET +
	       sizeof(struct shadow_vcpu_state) * num_vcpus;
}


#endif /* __ARM64_KVM_NVHE_PKVM_H__ */
