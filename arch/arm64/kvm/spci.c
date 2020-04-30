// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Will Deacon <will@kernel.org>
 */

#include <linux/kvm_host.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>

#include <kvm/arm_spci.h>

static struct kvm_spci_memory spci_part_mem[OF_MAX_RESERVED_MEM_REGIONS];
static struct reserved_mem *spci_hyp_mem;

static LIST_HEAD(spci_partitions);

static const struct of_device_id spci_of_match[] = {
	{ .compatible = "arm,spci-0.9-hypervisor" },
	{ },
};

static const struct of_device_id spci_part_of_match[] = {
	{ .compatible = "arm,spci-0.9-partition" },
	{ },
};

static int spci_ipa_range_overlaps(struct kvm_spci_partition *part,
				   struct kvm_spci_memory *spci_mem)
{
	int i;
	phys_addr_t this_start = spci_mem->ipa_base;
	phys_addr_t this_end = spci_mem->ipa_size + this_start;

	for (i = 0; i < part->nr_mems; ++i) {
		phys_addr_t start = part->mems[i]->ipa_base;
		phys_addr_t end = part->mems[i]->ipa_size + start;

		if (this_start >= start && this_start < end)
			return -EEXIST;

		if (this_end > start && this_end <= end)
			return -EEXIST;
	}

	return 0;
}

static struct kvm_spci_memory *
spci_parse_partition_mem(struct kvm_spci_partition *part,
			 struct device_node *mem_np)
{
	int na, ns;
	const __be32 *prop;
	struct reserved_mem *rmem;
	struct kvm_spci_memory *spci_mem;

	rmem = of_reserved_mem_lookup(mem_np);
	if (!rmem)
		return NULL;

	prop = of_get_property(mem_np, "ipa-range", NULL);
	if (!prop)
		return NULL;;

	na = of_n_addr_cells(mem_np);
	ns = of_n_size_cells(mem_np);
	spci_mem = rmem->priv;
	spci_mem->ipa_base = of_read_number(prop, na);
	spci_mem->ipa_size = of_read_number(prop + na, ns);

	/* TODO: For now, force the reserved region to be static. */
	if (!rmem->base)
		return NULL;

	/*
	 * TODO:
	 * For now, force the guest region to be the same size as the
	 * reservation. We may want to relax this in future to allow a bigger
	 * IPA range with on-demand allocation of pages for the region that
	 * isn't backed by the reservation.
	 */
	if (spci_mem->ipa_size != rmem->size)
		return NULL;

	/* TODO: Might be able to relax this to 4k? */
	if (!PAGE_ALIGNED(spci_mem->ipa_base) ||
	    !PAGE_ALIGNED(spci_mem->ipa_size))
		return NULL;

	if (spci_mem->ipa_size >> PAGE_SHIFT > KVM_MEM_MAX_NR_PAGES)
		return NULL;

	/* TODO: Check against kvm_ipa_limit? */

	spci_mem->prot = KVM_SPCI_MEM_PROT_R |
			 KVM_SPCI_MEM_PROT_W |
			 KVM_SPCI_MEM_PROT_X;

	if (of_property_read_bool(mem_np, "read-only"))
		spci_mem->prot &= ~KVM_SPCI_MEM_PROT_W;

	if (of_property_read_bool(mem_np, "non-executable"))
		spci_mem->prot &= ~KVM_SPCI_MEM_PROT_X;

	/* TODO: support all protection modes. */
	if (!(spci_mem->prot & KVM_SPCI_MEM_PROT_R))
		return NULL;
	if (!(spci_mem->prot & KVM_SPCI_MEM_PROT_X))
		return NULL;

	return spci_ipa_range_overlaps(part, spci_mem) ? NULL : spci_mem;
}

static struct kvm_spci_partition *
spci_alloc_partition(struct device_node *part_np)
{
	int i, nmems;
	struct kvm_spci_partition *part;

	nmems = of_property_count_u32_elems(part_np, "memory-region");
	if (nmems <= 0)
		return NULL;

	if (nmems > KVM_PRIVATE_MEM_SLOTS)
		return NULL;

	part = kzalloc(sizeof(*part) + nmems * sizeof(void *), GFP_KERNEL);
	if (!part)
		return NULL;

	for (i = 0; i < nmems; ++i) {
		struct kvm_spci_memory *spci_mem;
		struct device_node *mem_np;

		mem_np = of_parse_phandle(part_np, "memory-region", i);
		if (!mem_np)
			continue;

		if (!of_device_is_available(mem_np))
			goto next_put_node;

		spci_mem = spci_parse_partition_mem(part, mem_np);
		if (!spci_mem)
			goto next_put_node;

		part->mems[part->nr_mems++] = spci_mem;
next_put_node:
		of_node_put(mem_np);
	}

	if (!part->nr_mems) {
		kfree(part);
		part = NULL;
	}

	return part;
}

static int spci_parse_partition_entry_point(struct kvm_spci_partition *part,
					    struct device_node *part_np)
{
	int na = of_n_addr_cells(part_np);
	const __be32 *prop = of_get_property(part_np, "entry-point", NULL);
	int i;

	if (!prop)
		return -ENODEV;

	part->entry_point = of_read_number(prop, na);

	/*
	 * Ensure the entry point is within a preallocated memory region so that
	 * the partition cannot be compromised by entering at user space
	 * controlled memory.
	 */
	for (i = 0; i < part->nr_mems; ++i) {
		struct kvm_spci_memory *mem = part->mems[i];

		if (part->entry_point >= mem->ipa_base &&
		    part->entry_point < mem->ipa_base + mem->ipa_size)
			break;
	}

	if (i == part->nr_mems)
		return -EINVAL;

	return 0;
}

static struct kobj_type spci_part_ktype = {
	.sysfs_ops = &kobj_sysfs_ops,
};

#define kobj_to_part(kobj) container_of(kobj, struct kvm_spci_partition, kobj)
#define SPCI_PART_ATTR_RO(_name, _fmt, ...)				\
static ssize_t _name##_show(struct kobject *kobj,			\
			    struct kobj_attribute *attr,		\
			    char *buf)					\
{									\
	struct kvm_spci_partition *part = kobj_to_part(kobj);		\
									\
	return sprintf(buf, _fmt, __VA_ARGS__);				\
}									\
static struct kobj_attribute spci_part_attr_##_name = __ATTR_RO(_name)

SPCI_PART_ATTR_RO(uuid, "%pU\n", &part->uuid);
SPCI_PART_ATTR_RO(vcpus, "%d\n", part->nr_vcpus);
SPCI_PART_ATTR_RO(exec_state, "%s\n", part->is_32bit ? "AArch32" : "AArch64");

static struct attribute *spci_part_attrs[] = {
	&spci_part_attr_uuid.attr,
	&spci_part_attr_vcpus.attr,
	&spci_part_attr_exec_state.attr,
	NULL,
};

static const struct attribute_group spci_part_attr_group = {
	.attrs = spci_part_attrs,
};

static struct kobject *spci_kobj;

static int spci_partition_create_sysfs(struct kvm_spci_partition *part)
{
	int err;

	err = kobject_init_and_add(&part->kobj, &spci_part_ktype, spci_kobj,
				   "partition%d", part->id);
	if (err)
		goto out;

	err = sysfs_create_group(&part->kobj, &spci_part_attr_group);
	if (err)
		goto out_put_kobj;

	return 0;

out_put_kobj:
	kobject_put(&part->kobj);
out:
	return err;
}

static int spci_parse_partitions(struct device_node *spci_np)
{
	struct device_node *np, *prev_np = spci_np;
	const char *pfx = "Ignoring SPCI partition";
	int nr_parts = 0;

	while ((np = of_find_matching_node(prev_np, spci_part_of_match))) {
		struct kvm_spci_partition *part;
		const char *exec_state, *uuid;

		of_node_put(prev_np);
		prev_np = np;

		part = spci_alloc_partition(np);
		if (!part) {
			kvm_err("%s: failed to allocate partition\n", pfx);
			continue;
		}

		if (spci_parse_partition_entry_point(part, np)) {
			kvm_err("%s: failed to parse \"entry-point\" property\n",
				pfx);
			goto next_free_part;
		}

		if (of_property_read_u32(np, "nr-exec-ctxs", &part->nr_vcpus)) {
			kvm_err("%s: failed to parse \"nr-exec-ctxs\" property\n",
				pfx);
			goto next_free_part;
		}

		if (part->nr_vcpus > KVM_MAX_VCPUS) {
			kvm_err("%s: invalid \"nr-exec-ctxs\" property (%u)\n",
				pfx, part->nr_vcpus);
			goto next_free_part;
		}

		if (of_property_read_string(np, "exec-state", &exec_state)) {
			kvm_err("%s: failed to parse \"exec-state\" property\n",
				pfx);
			goto next_free_part;
		}

		if (!strcmp(exec_state, "AArch64")) {
			part->is_32bit = false;
		} else if (!strcmp(exec_state, "AArch32")) {
			part->is_32bit = true;
		} else {
			kvm_err("%s: invalid \"exec-state\" property (%s)\n",
				pfx, exec_state);
			goto next_free_part;
		}

		if (of_property_read_string(np, "uuid", &uuid)) {
			kvm_err("%s: failed to parse \"uuid\" property\n",
				pfx);
			goto next_free_part;
		}

		if (uuid_parse(uuid, &part->uuid)) {
			kvm_err("%s: invalid \"uuid\" property (%s)\n",
				pfx, uuid);
			goto next_free_part;
		}

		part->id = nr_parts;
		if (spci_partition_create_sysfs(part)) {
			kvm_err("%s: failed to create sysfs entries\n", pfx);
			goto next_free_part;
		}
		++nr_parts;

		INIT_LIST_HEAD(&part->list);
		list_add(&part->list, &spci_partitions);
		continue;
next_free_part:
		kfree(part);
	}

	of_node_put(prev_np);
	return list_empty(&spci_partitions) ? -ENODEV : 0;
}

static int spci_parse_dt_node(void)
{
	struct device_node *mem_np, *spci_np;
	int ret = 0;

	spci_np = of_find_matching_node(NULL, spci_of_match);
	if (!spci_np) {
		kvm_err("Failed to find SPCI devicetree node\n");
		return -ENODEV;
	}

	mem_np = of_parse_phandle(spci_np, "memory-region", 0);
	if (!mem_np) {
		kvm_err("Failed to parse SPCI \"memory-region\" phandle\n");
		ret = -ENODEV;
		goto out_put_spci_node;
	}

	if (of_reserved_mem_lookup(mem_np) != spci_hyp_mem) {
		kvm_err("Failed to find reserved memory for SPCI \"memory-region\"\n");
		ret = -EINVAL;
		goto out_put_mem_node;
	}

	if (!of_device_is_available(mem_np)) {
		kvm_err("SPCI \"memory-region\" is disabled; failing to initialise\n");
		ret = -ENODEV;
		goto out_put_mem_node;
	}

	ret = spci_parse_partitions(spci_np);
out_put_mem_node:
	of_node_put(mem_np);
out_put_spci_node:
	of_node_put(spci_np);
	return ret;
}

static void spci_dump_partitions(void)
{
	struct kvm_spci_partition *part;

	list_for_each_entry(part, &spci_partitions, list) {
		int i;

		kvm_info("SPCI partition:\n");
		kvm_info("  UUID: %pU\n", &part->uuid);
		kvm_info("  Entry point: 0x%llx\n", part->entry_point);
		kvm_info("  VCPUs: %d\n", part->nr_vcpus);
		kvm_info("  Execution state: %s\n",
			 part->is_32bit ? "AArch32" : "AArch64");

		kvm_info("  Memory regions:\n");
		for (i = 0; i < part->nr_mems; ++i) {
			struct kvm_spci_memory *mem = part->mems[i];
			phys_addr_t pa_end = mem->rmem->base + mem->rmem->size;
			phys_addr_t ipa_end = mem->ipa_base + mem->ipa_size;

			kvm_info("    [%02d]: PA: %pa-%pa\n",
				 i, &mem->rmem->base, &pa_end);
			kvm_info("          IPA: %pa-%pa\t(%s%s%s)\n",
				 &mem->ipa_base, &ipa_end,
				 mem->prot & KVM_SPCI_MEM_PROT_R ? "r" : "",
				 mem->prot & KVM_SPCI_MEM_PROT_W ? "w" : "",
				 mem->prot & KVM_SPCI_MEM_PROT_X ? "x" : "");
		}
	}
}

static int part_link(struct kvm *kvm, struct kvm_spci_partition *part)
{
	if (cmpxchg(&part->kvm, NULL, kvm) != NULL)
		return -EBUSY;

	kvm->arch.spci_part = part;
	return 0;
}

static void part_unlink(struct kvm *kvm)
{
	/* TODO: should the partition be marked as unusable now? */
	WARN_ON(cmpxchg(&kvm->arch.spci_part->kvm, kvm, NULL) != kvm);
	kvm->arch.spci_part = NULL;
}

static struct kvm_spci_partition *part_get_linked(struct kvm *kvm)
{
	struct kvm_spci_partition *part = kvm->arch.spci_part;

	WARN_ON(part && part->kvm != kvm);
	return part;
}

int kvm_spci_init(void)
{
	int ret;

	spci_kobj = kobject_create_and_add("spci", hypervisor_kobj);
	if (!spci_kobj)
		return -ENOMEM;

	ret = spci_parse_dt_node();
	if (ret)
		return ret;

	/* TODO: Throw this stuff at EL2 */

	spci_dump_partitions();
	kvm_info("SPCI initialised\n");
	return 0;
}

bool kvm_spci_supported(void)
{
	return !list_empty(&spci_partitions);
}

int kvm_spci_init_vm(struct kvm *kvm, unsigned long type)
{
	unsigned long attach_id =
		(type & KVM_VM_TYPE_ARM_SPCI_ATTACH_ID_MASK)
		>> KVM_VM_TYPE_ARM_SPCI_ATTACH_ID_SHIFT;
	struct kvm_spci_partition *part;
	int ret;
	int i;

	if (!(type & KVM_VM_TYPE_ARM_SPCI_ATTACH))
		return attach_id ? -EINVAL : 0;

	// TODO: validate the IPA size is large enough for the memory regions

	if (!kvm_spci_supported())
		return -EINVAL;

	list_for_each_entry(part, &spci_partitions, list)
		if (part->id == attach_id)
			break;

	if (part->id != attach_id)
		return -ENOENT;

	ret = part_link(kvm, part);
	if (ret)
		return ret;

	if (part->nr_vcpus > kvm->arch.max_vcpus) {
		kvm_err("Partition requires %d vCPUs but max is %d\n",
			part->nr_vcpus, kvm->arch.max_vcpus);
		return -EDQUOT; // XXX: ?????
	}

	kvm->arch.max_vcpus = part->nr_vcpus;

	mutex_lock(&kvm->slots_lock);
	for (i = 0; i < part->nr_mems; ++i) {
		struct kvm_spci_memory *mem = part->mems[i];
		struct kvm_userspace_memory_region m = {
			.slot = KVM_ARM_SPCI_MEM_SLOT_BASE + i,
			.flags = KVM_ARM_MEM_PHYSICAL,
			.guest_phys_addr = mem->ipa_base,
			.memory_size = mem->rmem->size,
			.userspace_addr = mem->rmem->base,
		};

		if (!(mem->prot & KVM_SPCI_MEM_PROT_W))
			m.flags |= KVM_MEM_READONLY;

		/* TODO: read and execute protect. */

		ret = __kvm_set_memory_region(kvm, &m);
		if (ret)
			break;
	}
	mutex_unlock(&kvm->slots_lock);

	if (ret)
		return ret;

	return 0;
}

void kvm_spci_destroy_vm(struct kvm *kvm)
{
	part_unlink(kvm);
}

int kvm_spci_check_vcpu_init_features(const struct kvm_vcpu *vcpu,
				      const struct kvm_vcpu_init *init)
{
	const struct kvm_spci_partition *part = part_get_linked(vcpu->kvm);
	bool el1_32bit;

	if (!part)
		return 0;

	el1_32bit = init->features[0] & (1 << KVM_ARM_VCPU_EL1_32BIT);
	if (el1_32bit != part->is_32bit)
		return -EINVAL;

	return 0;
}

int kvm_spci_vcpu_first_run_init(struct kvm_vcpu *vcpu)
{
	const struct kvm_spci_partition *part = part_get_linked(vcpu->kvm);

	if (!part)
		return 0;

	vcpu_gp_regs(vcpu)->regs.pc = part->entry_point;
	return 0;
}

int kvm_spci_vcpu_reg_list_num(struct kvm_vcpu *vcpu, unsigned long *num)
{
	const struct kvm_spci_partition *part = part_get_linked(vcpu->kvm);

	if (!part)
		return 0;

	if (likely(vcpu->arch.has_run_once))
		*num = 0;
	else
		*num = 8;

	return 1;
}

int kvm_spci_vcpu_reg_list(struct kvm_vcpu *vcpu, u64 __user *uindices)
{
	const struct kvm_spci_partition *part = part_get_linked(vcpu->kvm);
	u64 i;

	if (!part)
		return 1;

	if (likely(vcpu->arch.has_run_once))
		return 1;

	for (i = 0; i < 16; i += 2) {
		u64 reg = KVM_REG_ARM64 | KVM_REG_ARM_CORE
			| KVM_REG_SIZE_U64 | i;

		if (uindices) {
			if (put_user(reg, uindices))
				return -EFAULT;
			++uindices;
		}
	}

	return 0;
}

/*
 * Checks the registers can be accessed by user space. If the vCPU is part of an
 * SPCI partition, the only registers that can be accessed are x0-7 and,
 * further, they can only be accessed before the first run. This allows user
 * space to pass in some initial arguments but does not allow it the
 * subsequently modify or observe the registers state of the vCPU.
 */
int kvm_spci_check_vcpu_access_reg(struct kvm_vcpu *vcpu,
				   struct kvm_one_reg *reg)
{
	const struct kvm_spci_partition *part = part_get_linked(vcpu->kvm);

	if (!part)
		return 0;

	if (likely(vcpu->arch.has_run_once))
		return -EPERM;

	switch (core_reg_offset_from_id(reg->id)) {
	case KVM_REG_ARM_CORE_REG(regs.regs[0]) ...
	     KVM_REG_ARM_CORE_REG(regs.regs[7]):
		     break;
	default:
		return -EPERM;
	}

	return 0;
}

/* Early memory reservation parsing. */
static int __init spci_rmem_err(const char *type, struct reserved_mem *rmem,
				const char *reason)
{
	pr_err("Ignoring SPCI %s memory reservation of %pa bytes at %pa [%s]\n",
		type, &rmem->size, &rmem->base, reason);
	return -EINVAL;
}

static int __init spci_rmem_check(const char *type, struct reserved_mem *rmem)
{
	unsigned long node = rmem->fdt_node;
	bool nomap = of_get_flat_dt_prop(node, "no-map", NULL);
	bool reusable = of_get_flat_dt_prop(node, "reusable", NULL);

	if (nomap)
		return spci_rmem_err(type, rmem, "\"no-map\" property unsupported");

	if (reusable)
		return spci_rmem_err(type, rmem, "\"reusable\" property unsupported");

	if (!PAGE_ALIGNED(rmem->base))
		return spci_rmem_err(type, rmem, "physical base is not page-aligned");

	if (!PAGE_ALIGNED(rmem->size))
		return spci_rmem_err(type, rmem, "size is not page-aligned");

	return 0;
}

static int __init spci_rmem_partition_early_setup(struct reserved_mem *rmem)
{
	static int __initdata i = 0;
	int ret = spci_rmem_check("partition", rmem);

	if (!ret) {
		spci_part_mem[i].rmem = rmem;
		rmem->priv = &spci_part_mem[i++];
	}

	return ret;
}
RESERVEDMEM_OF_DECLARE(spci_partition, "arm,spci-0.9-partition-memory-region",
		       spci_rmem_partition_early_setup);

static int __init spci_rmem_hypervisor_early_setup(struct reserved_mem *rmem)
{
	int ret;

	if (spci_hyp_mem) {
		pr_err("Ignoring superfluous SPCI hypervisor memory reservation at %pa\n",
			&rmem->base);
		return -EEXIST;
	}

	ret = spci_rmem_check("hypervisor", rmem);
	if (!ret)
		spci_hyp_mem = rmem;
	return ret;
}
RESERVEDMEM_OF_DECLARE(spci_hypervisor, "arm,spci-0.9-hypervisor-memory-region",
		       spci_rmem_hypervisor_early_setup);
