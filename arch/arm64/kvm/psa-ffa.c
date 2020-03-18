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

#include <kvm/arm-psa-ffa.h>

static struct kvm_ffa_memory ffa_part_mem[OF_MAX_RESERVED_MEM_REGIONS];
static struct reserved_mem *ffa_hyp_mem;

static LIST_HEAD(ffa_partitions);

static const struct of_device_id ffa_of_match[] = {
	{ .compatible = "arm,psa-ffa-1.0-hypervisor" },
	{ },
};

static const struct of_device_id ffa_part_of_match[] = {
	{ .compatible = "arm,psa-ffa-1.0-partition" },
	{ },
};

static int ffa_ipa_range_overlaps(struct kvm_ffa_partition *part,
				   struct kvm_ffa_memory *ffa_mem)
{
	int i;
	phys_addr_t this_start = ffa_mem->ipa_base;
	phys_addr_t this_end = ffa_mem->ipa_size + this_start;

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

static struct kvm_ffa_memory *
ffa_parse_partition_mem(struct kvm_ffa_partition *part,
			 struct device_node *mem_np)
{
	int na, ns;
	const __be32 *prop;
	struct reserved_mem *rmem;
	struct kvm_ffa_memory *ffa_mem;

	rmem = of_reserved_mem_lookup(mem_np);
	if (!rmem)
		return NULL;

	prop = of_get_property(mem_np, "ipa-range", NULL);
	if (!prop)
		return NULL;;

	na = of_n_addr_cells(mem_np);
	ns = of_n_size_cells(mem_np);
	ffa_mem = rmem->priv;
	ffa_mem->ipa_base = of_read_number(prop, na);
	ffa_mem->ipa_size = of_read_number(prop + na, ns);

	/*
	 * TODO:
	 * For now, force the guest region to be the same size as the
	 * reservation. We may want to relax this in future to allow a bigger
	 * IPA range with on-demand allocation of pages for the region that
	 * isn't backed by the reservation.
	 */
	if (ffa_mem->ipa_size != rmem->size)
		return NULL;

	/* TODO: Might be able to relax this to 4k? */
	if (!PAGE_ALIGNED(ffa_mem->ipa_base) ||
	    !PAGE_ALIGNED(ffa_mem->ipa_size))
		return NULL;

	/* TODO: Check against kvm_ipa_limit? */

	ffa_mem->prot = KVM_FFA_MEM_PROT_R |
			 KVM_FFA_MEM_PROT_W |
			 KVM_FFA_MEM_PROT_X;

	if (of_property_read_bool(mem_np, "read-only"))
		ffa_mem->prot &= ~KVM_FFA_MEM_PROT_W;

	if (of_property_read_bool(mem_np, "non-executable"))
		ffa_mem->prot &= ~KVM_FFA_MEM_PROT_X;

	return ffa_ipa_range_overlaps(part, ffa_mem) ? NULL : ffa_mem;
}

static struct kvm_ffa_partition *
ffa_alloc_partition(struct device_node *part_np)
{
	int i, nmems;
	struct kvm_ffa_partition *part;

	nmems = of_property_count_u32_elems(part_np, "memory-region");
	if (nmems <= 0)
		return NULL;

	part = kzalloc(sizeof(*part) + nmems * sizeof(void *), GFP_KERNEL);
	if (!part)
		return NULL;

	for (i = 0; i < nmems; ++i) {
		struct kvm_ffa_memory *ffa_mem;
		struct device_node *mem_np;

		mem_np = of_parse_phandle(part_np, "memory-region", i);
		if (!mem_np)
			continue;

		if (!of_device_is_available(mem_np))
			goto next_put_node;

		ffa_mem = ffa_parse_partition_mem(part, mem_np);
		if (!ffa_mem)
			goto next_put_node;

		part->mems[part->nr_mems++] = ffa_mem;
next_put_node:
		of_node_put(mem_np);
	}

	if (!part->nr_mems) {
		kfree(part);
		part = NULL;
	}

	return part;
}

static int ffa_parse_partition_entry_point(struct kvm_ffa_partition *part,
					    struct device_node *part_np)
{
	int na = of_n_addr_cells(part_np);
	const __be32 *prop = of_get_property(part_np, "entry-point", NULL);

	if (!prop)
		return -ENODEV;

	part->entry_point = of_read_number(prop, na);
	return 0;
}

static int ffa_parse_partitions(struct device_node *ffa_np)
{
	struct device_node *np, *prev_np = ffa_np;
	const char *pfx = "Ignoring FFA partition";

	while ((np = of_find_matching_node(prev_np, ffa_part_of_match))) {
		struct kvm_ffa_partition *part;
		const char *exec_state, *uuid;

		of_node_put(prev_np);
		prev_np = np;

		part = ffa_alloc_partition(np);
		if (!part) {
			kvm_err("%s: failed to allocate partition\n", pfx);
			continue;
		}

		if (ffa_parse_partition_entry_point(part, np)) {
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

		INIT_LIST_HEAD(&part->list);
		list_add(&part->list, &ffa_partitions);
		continue;
next_free_part:
		kfree(part);
	}

	of_node_put(prev_np);
	return list_empty(&ffa_partitions) ? -ENODEV : 0;
}

static int ffa_parse_dt_node(void)
{
	struct device_node *mem_np, *ffa_np;
	int ret = 0;

	ffa_np = of_find_matching_node(NULL, ffa_of_match);
	if (!ffa_np) {
		kvm_err("Failed to find FFA devicetree node\n");
		return -ENODEV;
	}

	mem_np = of_parse_phandle(ffa_np, "memory-region", 0);
	if (!mem_np) {
		kvm_err("Failed to parse FFA \"memory-region\" phandle\n");
		ret = -ENODEV;
		goto out_put_ffa_node;
	}

	if (of_reserved_mem_lookup(mem_np) != ffa_hyp_mem) {
		kvm_err("Failed to find reserved memory for FFA \"memory-region\"\n");
		ret = -EINVAL;
		goto out_put_mem_node;
	}

	if (!of_device_is_available(mem_np)) {
		kvm_err("FFA \"memory-region\" is disabled; failing to initialise\n");
		ret = -ENODEV;
		goto out_put_mem_node;
	}

	ret = ffa_parse_partitions(ffa_np);
out_put_mem_node:
	of_node_put(mem_np);
out_put_ffa_node:
	of_node_put(ffa_np);
	return ret;
}

static void ffa_dump_partitions(void)
{
	struct kvm_ffa_partition *part;

	list_for_each_entry(part, &ffa_partitions, list) {
		int i;

		kvm_info("FFA partition:\n");
		kvm_info("  UUID: %pU\n", &part->uuid);
		kvm_info("  Entry point: 0x%llx\n", part->entry_point);
		kvm_info("  VCPUs: %d\n", part->nr_vcpus);
		kvm_info("  Execution state: %s\n",
			 part->is_32bit ? "AArch32" : "AArch64");

		kvm_info("  Memory regions:\n");
		for (i = 0; i < part->nr_mems; ++i) {
			struct kvm_ffa_memory *mem = part->mems[i];
			phys_addr_t pa_end = mem->rmem->base + mem->rmem->size;
			phys_addr_t ipa_end = mem->ipa_base + mem->ipa_size;

			kvm_info("    [%02d]: PA: %pa-%pa\n",
				 i, &mem->rmem->base, &pa_end);
			kvm_info("          IPA: %pa-%pa\t(%s%s%s)\n",
				 &mem->ipa_base, &ipa_end,
				 mem->prot & KVM_FFA_MEM_PROT_R ? "r" : "",
				 mem->prot & KVM_FFA_MEM_PROT_W ? "w" : "",
				 mem->prot & KVM_FFA_MEM_PROT_X ? "x" : "");
		}
	}
}

int kvm_ffa_init(void)
{
	int ret = ffa_parse_dt_node();

	if (ret)
		return ret;

	/* TODO: Throw this stuff at EL2 */

	ffa_dump_partitions();
	kvm_info("FFA initialised\n");
	return 0;
}

/* Early memory reservation parsing. */
static int __init ffa_rmem_err(const char *type, struct reserved_mem *rmem,
				const char *reason)
{
	pr_err("Ignoring FFA %s memory reservation of %pa bytes at %pa [%s]\n",
		type, &rmem->size, &rmem->base, reason);
	return -EINVAL;
}

static int __init ffa_rmem_check(const char *type, struct reserved_mem *rmem)
{
	unsigned long node = rmem->fdt_node;
	bool nomap = of_get_flat_dt_prop(node, "no-map", NULL);
	bool reusable = of_get_flat_dt_prop(node, "reusable", NULL);

	if (nomap)
		return ffa_rmem_err(type, rmem, "\"no-map\" property unsupported");

	if (reusable)
		return ffa_rmem_err(type, rmem, "\"reusable\" property unsupported");

	if (!PAGE_ALIGNED(rmem->base))
		return ffa_rmem_err(type, rmem, "physical base is not page-aligned");

	if (!PAGE_ALIGNED(rmem->size))
		return ffa_rmem_err(type, rmem, "size is not page-aligned");

	return 0;
}

static int __init ffa_rmem_partition_early_setup(struct reserved_mem *rmem)
{
	static int __initdata i = 0;
	int ret = ffa_rmem_check("partition", rmem);

	if (!ret) {
		ffa_part_mem[i].rmem = rmem;
		rmem->priv = &ffa_part_mem[i++];
	}

	return ret;
}
RESERVEDMEM_OF_DECLARE(ffa_partition,
		       "arm,psa-ffa-1.0-partition-memory-region",
		       ffa_rmem_partition_early_setup);

static int __init ffa_rmem_hypervisor_early_setup(struct reserved_mem *rmem)
{
	int ret;

	if (ffa_hyp_mem) {
		pr_err("Ignoring superfluous FFA hypervisor memory reservation at %pa\n",
			&rmem->base);
		return -EEXIST;
	}

	ret = ffa_rmem_check("hypervisor", rmem);
	if (!ret)
		ffa_hyp_mem = rmem;
	return ret;
}
RESERVEDMEM_OF_DECLARE(ffa_hypervisor,
		       "arm,psa-ffa-1.0-hypervisor-memory-region",
		       ffa_rmem_hypervisor_early_setup);
