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
	struct kvm *kvm = vcpu->kvm;

	if (!kvm_vm_is_protected(kvm))
		return 0;

	if (!vcpu->vcpu_id) {
		int i;
		struct kvm_memory_slot *slot = kvm->arch.pkvm.firmware_slot;
		struct user_pt_regs *regs = vcpu_gp_regs(vcpu);

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

static int pkvm_init_el2_context(struct kvm *kvm)
{
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
	 * - ...
	 */
	kvm_pr_unimpl("Stage-2 protection is not yet implemented; ignoring\n");
	return 0;
#else
	return __do_not_call_this_function(kvm->arch.pkvm.firmware_slot);
#endif
}

static int pkvm_init_firmware_slot(struct kvm *kvm, u64 slotid)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *slot;

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

	ret = pkvm_init_el2_context(kvm);
	if (ret)
		pkvm_teardown_firmware_slot(kvm);

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

	kvm->arch.pkvm.enabled = true;
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
