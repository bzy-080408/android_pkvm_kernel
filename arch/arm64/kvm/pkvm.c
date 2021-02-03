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

static struct reserved_mem *pkvm_firmware_mem;

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

int kvm_arm_vcpu_pkvm_init(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_arch_core *core_state = &vcpu->arch.core_state;
	struct kvm *kvm = vcpu->kvm;

	if (!kvm_vm_is_protected(kvm))
		return 0;

	if (!vcpu->vcpu_id) {
		int i;
		struct kvm_memory_slot *slot = kvm->arch.pkvm.firmware_slot;
		struct user_pt_regs *regs = vcpu_gp_regs(core_state);

		if (!slot)
			return 0;

		/* X0 - X14 provided by VMM (preserved) */

		/* X15: Boot protocol version */
		regs->regs[15] = 0;

		/* X16 - X30 reserved (zeroed) */
		for (i = 16; i <= 30; ++i)
			regs->regs[i] = 0;

		/* PC: IPA base of bootloader memslot */
		regs->pc = slot->base_gfn << PAGE_SHIFT;

		/* SP: IPA end of bootloader memslot */
		regs->sp = (slot->base_gfn + slot->npages) << PAGE_SHIFT;
	} else if (!test_bit(KVM_ARM_VCPU_POWER_OFF, vcpu->arch.features)) {
		if (kvm->arch.pkvm.firmware_slot)
			return -EPERM;
	}

	return 0;
}

static int __do_not_call_this_function(struct kvm_memory_slot *slot)
{
	int uncopied;
	size_t sz = pkvm_firmware_mem->size;
	void *src, __user *dst = (__force void __user *)slot->userspace_addr;

	if (clear_user(dst, slot->npages * PAGE_SIZE))
		return -EFAULT;

	src = memremap(pkvm_firmware_mem->base, sz, MEMREMAP_WB);
	if (!src)
		return -EFAULT;

	//((u32 *)src)[0] = 0xaa0f03e0; // MOV	X0, X15
	//((u32 *)src)[1] = 0xd61f0200; // BR	X16
	uncopied = copy_to_user(dst, src, sz);
	memunmap(src);
	return uncopied ? -EFAULT : 0;
}

static size_t shadow_size(const struct kvm *kvm)
{
	/*
	 * Allocate shadow space only for struct kvm and its corresponding
	 * kvm_vcpu_arch_core structures.
	 * The remaining structs are not needed (for now).
	 */
	return sizeof(struct kvm) +
	       sizeof(struct kvm_vcpu_arch_core) * kvm->created_vcpus;
}

/*
 * Copy the host's kvm and core states into the donated shadow memory.
 * struct kvm is placed first, followed by a copy of all its cores.
 *
 * The copies are all shallow copies, without any pointer values being fixed or
 * reset. It's up to hyp to fix these values.
 */
static void copy_shadow_structs(void *shadow_addr, const struct kvm *host_kvm)
{
	int i;
	struct kvm_vcpu_arch_core *shadow_cores;
	struct kvm *kvm = shadow_addr;

	memcpy(kvm, host_kvm, sizeof(*kvm));

	/* Place shadow vcpus immediately after the shadow kvm struct. */
	shadow_cores = (struct kvm_vcpu_arch_core *)
		       ((unsigned long)shadow_addr + sizeof(*kvm));

	for (i = 0; i < host_kvm->created_vcpus; i++) {
		struct kvm_vcpu_arch_core *shadow_core = &shadow_cores[i];
		const struct kvm_vcpu_arch_core *host_core = &host_kvm->vcpus[i]->arch.core_state;

		memcpy(shadow_core, host_core, sizeof(*shadow_core));
	}
}

/*
 * Initializes the state of the host's version of the vcpu structure.
 */
static void init_host_core(struct kvm_vcpu_arch_core *core, int shadow_handle)
{
	core->pkvm.shadow_handle = shadow_handle;

	/* Set the PC to 0x0 so it doesn't confuse on traces and debugs. */
	//*vcpu_pc(core) = 0x0;

	/*
	 * Treat the guest as if it were in EL1/H mode.
	 * For WFI: What matters here is whether it's treated as privileged.
	 * For exception injection: inject into the guest's kernel.
	 * Ensure that everything else is cleared.
	 */
	//*vcpu_cpsr(core) = PSR_MODE_EL1h;
}

/*
 * Allocate and donate memory for EL2 shadow structs.
 *
 * Allocates space for struct kvm and all its created vcpus (struct kvm_vcpu).
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
	shadow_order = get_order(shadow_size(kvm));
	shadow_pages = alloc_pages(GFP_KERNEL, shadow_order);
	if (!shadow_pages) {
		ret = -ENOMEM;
		goto err_dealloc;
	}
	shadow_addr = page_address(shadow_pages);
	shadow_total_size = (1u << shadow_order) * PAGE_SIZE;

	/*
	 * Copy the shadow structs to the memory to be donated.
	 *
	 * Places a copy of struct kvm first, followed by copies of all the
	 * struct vcpus.
	 *
	 * The copies are all shallow copies, without any pointer values being
	 * fixed or reset. It's up to hyp to fix these values.
	 */
	copy_shadow_structs(shadow_addr, kvm);

	/* Unmap the shadow memory at stage 1. Hyp will unmap it at stage 2. */
	unmap_kernel_range((u64) shadow_addr, shadow_total_size);

	/* Donate the shadow memory to hyp. */
	ret = kvm_call_hyp_nvhe(__pkvm_init_shadow,
				kvm, shadow_addr, shadow_total_size);
	if (ret < 0)
		goto err_dealloc;

	shadow_handle = ret;

	/* Store the handle given by hyp for reference in future calls. */
	kvm->arch.pkvm.shadow_handle = shadow_handle;

	/* Adjust the host's core state to reflect the new reality. */
	for (i = 0; i < kvm->created_vcpus; i++)
		init_host_core(&kvm->vcpus[i]->arch.core_state, shadow_handle);

	/* TODO: Only for debugging and sanity checking. */
	printk(KERN_ALERT
	       "%s:%d: SUCCESS: created_vcpus %d, shadow_order %u, shadow_num_pages %u, shadow_size(kvm) %lu, shadow_addr 0x%lx, sizeof(kvm) %lu, sizeof(kvm_vcpu_arch_core) %lu, ret %d, handle %d\n",
	       __func__, __LINE__, kvm->created_vcpus, shadow_order,
	       (1u << shadow_order), shadow_size(kvm),
	       (unsigned long)shadow_addr,
	       sizeof(*kvm), sizeof(struct kvm_vcpu_arch_core), ret,
	       kvm->arch.pkvm.shadow_handle);

	return 0;

err_dealloc:
	free_pages((unsigned long)shadow_addr, shadow_order);

err:
	return ret;
}

static int pkvm_init_el2_context(struct kvm *kvm)
{
	int ret = 0;

	ret = create_el2_shadow(kvm);

	if (ret < 0) {
		/* TODO: panic is for testing only. To be removed. */
		panic("create_el2_shadow failed.");
		return ret;
	}

#if 0
	/*
	 * TODO:
	 * Eventually, this will involve a call to EL2 to:
	 * - Register this VM as a protected VM
	 * - Provide pages for the firmware
	 * - Unmap memslots from the host
	 * - Force reset state and lock down access
	 * - Prevent attempts to run unknown vCPUs
	 * - Ensure that no vCPUs have previously entered the VM
	 * - Handle failures that happen after create_el2_shadow() is called.
	 * - ...
	 */
	kvm_pr_unimpl("Stage-2 protection is not yet implemented; ignoring\n");
	return 0;
#else
	if (!kvm->arch.pkvm.firmware_slot)
		return 0;

	return __do_not_call_this_function(kvm->arch.pkvm.firmware_slot);
#endif
}

static int pkvm_init_firmware_slot(struct kvm *kvm, u64 slotid)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;

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
