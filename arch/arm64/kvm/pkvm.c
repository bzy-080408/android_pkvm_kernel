// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM host (EL1) interface to Protected KVM (pkvm) code at EL2.
 *
 * Copyright (C) 2021 Google LLC
 * Author: Will Deacon <will@kernel.org>
 */

#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>

#include <hyp/include/nvhe/pkvm.h>

static struct reserved_mem *pkvm_firmware_mem;

/*
 * Initializes the state of the donated shadow memory.
 * Copy the host's vcpu states to the donated shadow memory.
 * The vm struct comes first, followed by a copy of all its vcpu states.
 */
static void init_shadow_structs(void *shadow_addr, const struct kvm *kvm)
{
	int i;
	struct shadow_vcpu_state *shadow_vcpu_states;

	/* Place vcpus' shadow state immediately after the shadow vm. */
	shadow_vcpu_states = (struct shadow_vcpu_state *)
			     ((unsigned long)shadow_addr + SHADOW_VCPUS_OFFSET);

	for (i = 0; i < kvm->created_vcpus; i++) {
		const struct kvm_vcpu *vcpu = kvm->vcpus[i];
		struct shadow_vcpu_state *shadow_vcpu_state =
			&shadow_vcpu_states[i];

		memcpy(&shadow_vcpu_state->vcpu, vcpu,
		       sizeof(shadow_vcpu_state->vcpu));
	}
}

/*
 * Updates the state of the host's version of the vcpu state.
 */
static void update_vcpu_state(struct kvm_vcpu *vcpu, int shadow_handle)
{
	vcpu->arch.pkvm.shadow_handle = shadow_handle;

	/* Set the PC to 0x0 so it doesn't confuse on traces and debugs. */
	//*ctxt_pc(vcpu_ctxt) = 0x0;
	/*
	 * Treat the guest as if it were in EL1/H mode.
	 * For WFI: What matters here is whether it's treated as privileged.
	 * For exception injection: inject into the guest's kernel.
	 * Ensure that everything else is cleared.
	 */
	//*ctxt_cpsr(vcpu_ctxt) = PSR_MODE_EL1h;
}

/*
 * Allocate and donate memory for EL2 shadow structs.
 *
 * Allocates space for the shadow state, which includes the shadow vm as well as
 * the shadow vcpu states.
 *
 * Unmaps the donated memory at stage 1.
 *
 * Stores an opaque handler in the kvm struct for future reference.
 *
 * Return 0 on success, negative error code on failure.
 */
static int create_el2_shadow(struct kvm *kvm)
{
	unsigned int shadow_order = 0;
	struct page *shadow_pages;
	void *shadow_addr = NULL;
	size_t shadow_total_size;
	int ret = 0;
	int shadow_handle;
	int i;

	if (kvm->created_vcpus < 1) {
		ret = -EINVAL;
		goto err;
	}

	/* Allocate memory to donate to hyp for the kvm and vcpu state. */
	/* TODO: alloc_pages allocates base-2 order pages, wastefull? */
	shadow_order = get_order(hyp_get_shadow_size(kvm->created_vcpus));
	shadow_pages = alloc_pages(GFP_KERNEL, shadow_order);

	if (!shadow_pages) {
		ret = -ENOMEM;
		goto err_dealloc;
	}

	shadow_addr = page_address(shadow_pages);
	shadow_total_size = (1u << shadow_order) * PAGE_SIZE;

	/* Initialize the shadow structs in the donated memory.	*/
	init_shadow_structs(shadow_addr, kvm);

	/* Unmap the shadow memory at stage 1. Hyp will unmap it at stage 2. */
	vunmap_range((u64)shadow_addr, (u64)(shadow_addr + shadow_total_size));

	/* Donate the shadow memory to hyp and let hyp initialize it. */
	ret = kvm_call_hyp_nvhe(__pkvm_init_shadow,
				kvm, shadow_addr, shadow_total_size);

	if (ret < 0)
		goto err_dealloc;

	shadow_handle = ret;

	/* Store the shadow handle given by hyp for future call reference. */
	kvm->arch.pkvm.shadow_handle = shadow_handle;

	/* Adjust host's vcpu state as it doesn't control it anymore. */
	for (i = 0; i < kvm->created_vcpus; i++)
		update_vcpu_state(kvm->vcpus[i], shadow_handle);

	/* TODO: Only for debugging and sanity checking. Will remove. */
	printk(KERN_ALERT
	       "%s:%d: SUCCESS: created_vcpus %d, shadow_order %u, shadow_num_pages %u, shadow_size(kvm) %lu, shadow_addr 0x%lx, sizeof(struct kvm) %lu, sizeof(struct kvm_vcpu) %lu, sizeof(struct kvm_shadow_vm) %lu, sizeof(struct shadow_vcpu_state) %lu, ret %d, handle %d\n",
	       __func__, __LINE__, kvm->created_vcpus, shadow_order,
	       (1u << shadow_order), hyp_get_shadow_size(kvm->created_vcpus),
	       (unsigned long)shadow_addr,
	       sizeof(struct kvm), sizeof(struct kvm_vcpu), sizeof(struct kvm_shadow_vm), sizeof(struct shadow_vcpu_state), ret,
	       kvm->arch.pkvm.shadow_handle);

	return 0;
err_dealloc:
	free_pages((unsigned long)shadow_addr, shadow_order);
err:
	return ret;
}

static int __init pkvm_firmware_rmem_err(struct reserved_mem *rmem,
					 const char *reason)
{
	phys_addr_t end = rmem->base + rmem->size;

	kvm_err("Ignoring pkvm guest firmware memory reservation [%pa - %pa]: %s\n",
		&rmem->base, &end, reason);
	return -EINVAL;
}

static int __init pkvm_firmware_rmem_init(struct reserved_mem *rmem)
{
	unsigned long node = rmem->fdt_node;

	if (kvm_get_mode() != KVM_MODE_PROTECTED)
		return pkvm_firmware_rmem_err(rmem, "protected mode not enabled");

	if (pkvm_firmware_mem)
		return pkvm_firmware_rmem_err(rmem, "duplicate reservation");

	if (!of_get_flat_dt_prop(node, "no-map", NULL))
		return pkvm_firmware_rmem_err(rmem, "missing \"no-map\" property");

	if (of_get_flat_dt_prop(node, "reusable", NULL))
		return pkvm_firmware_rmem_err(rmem, "\"reusable\" property unsupported");

	if (!PAGE_ALIGNED(rmem->base))
		return pkvm_firmware_rmem_err(rmem, "base is not page-aligned");

	if (!PAGE_ALIGNED(rmem->size))
		return pkvm_firmware_rmem_err(rmem, "size is not page-aligned");

	pkvm_firmware_mem = rmem;
	return 0;
}
RESERVEDMEM_OF_DECLARE(pkvm_firmware, "linux,pkvm-guest-firmware-memory",
		       pkvm_firmware_rmem_init);

static int pkvm_init_el2_context(struct kvm *kvm)
{
	int ret = 0;

	ret = create_el2_shadow(kvm);
	if (ret < 0) {
		/* TODO: panic is for testing only. To be removed. */
		panic("create_el2_shadow failed.");
		return ret;
	}

	kvm_pr_unimpl("Stage-2 protection is not yet implemented\n");
	return 0;
}

static int pkvm_init_firmware_slot(struct kvm *kvm, u64 slotid)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;

	/* Special case for testing */
	if (slotid == -1)
		return 0;

	if (slotid >= KVM_MEM_SLOTS_NUM || !pkvm_firmware_mem)
		return -EINVAL;

	slots = kvm_memslots(kvm);
	if (!slots)
		return -ENOENT;

	slot = id_to_memslot(slots, slotid);
	if (!slot)
		return -ENOENT;

	if (slot->flags)
		return -EINVAL;

	if ((slot->npages << PAGE_SHIFT) < pkvm_firmware_mem->size)
		return -ENOMEM;

	kvm->arch.pkvm.firmware_slot = slot;
	return 0;
}

static void pkvm_teardown_firmware_slot(struct kvm *kvm)
{
	kvm->arch.pkvm.firmware_slot = NULL;
}

static int pkvm_enable(struct kvm *kvm, u64 slotid)
{
	int ret;

	ret = pkvm_init_firmware_slot(kvm, slotid);
	if (ret)
		return ret;

	kvm->arch.pkvm.enabled = true;

	ret = pkvm_init_el2_context(kvm);

	if (ret) {
		kvm->arch.pkvm.enabled = false;
		pkvm_teardown_firmware_slot(kvm);
	}

	return ret;
}

static int pkvm_vm_ioctl_enable(struct kvm *kvm, u64 slotid)
{
	int ret = 0;

	mutex_lock(&kvm->lock);
	if (kvm_vm_is_protected(kvm)) {
		ret = -EPERM;
		goto out_kvm_unlock;
	}

	mutex_lock(&kvm->slots_lock);
	ret = pkvm_enable(kvm, slotid);
	if (ret)
		goto out_slots_unlock;

out_slots_unlock:
	mutex_unlock(&kvm->slots_lock);
out_kvm_unlock:
	mutex_unlock(&kvm->lock);
	return ret;
}

static int pkvm_vm_ioctl_info(struct kvm *kvm,
			      struct kvm_protected_vm_info __user *info)
{
	struct kvm_protected_vm_info kinfo = {
		.firmware_size = pkvm_firmware_mem ?
				 pkvm_firmware_mem->size :
				 0,
	};

	return copy_to_user(info, &kinfo, sizeof(kinfo)) ? -EFAULT : 0;
}

int kvm_arm_vm_ioctl_pkvm(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	if (cap->args[1] || cap->args[2] || cap->args[3])
		return -EINVAL;

	switch (cap->flags) {
	case KVM_CAP_ARM_PROTECTED_VM_FLAGS_ENABLE:
		return pkvm_vm_ioctl_enable(kvm, cap->args[0]);
	case KVM_CAP_ARM_PROTECTED_VM_FLAGS_INFO:
		return pkvm_vm_ioctl_info(kvm, (void __user *)cap->args[0]);
	default:
		return -EINVAL;
	}

	return 0;
}
