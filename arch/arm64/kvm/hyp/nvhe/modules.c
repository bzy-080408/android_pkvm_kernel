/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TODO: authorship
 */
#include <asm/bug.h>
#include <asm/kvm_host.h>
#include <asm/kvm_pkvm_module.h>

#include <nvhe/mem_protect.h>
#include <nvhe/memory.h>
#include <nvhe/modules.h>
#include <nvhe/mm.h>
#include <nvhe/serial.h>

static void __kvm_flush_dcache_to_poc(void *addr, size_t size)
{
	kvm_flush_dcache_to_poc((unsigned long)addr, (unsigned long)size);
}

#define MAX_MODULES 16

DEFINE_HYP_SPINLOCK(modules_lock);

struct pkvm_module {
	unsigned long id;
	void *hyp_text;
};

static struct pkvm_module modules[MAX_MODULES];

const struct pkvm_module_ops module_ops = {
	.create_private_mapping = __pkvm_create_private_mapping,
	.register_serial_driver = __pkvm_register_serial_driver,
	.puts = hyp_puts,
	.putx64 = hyp_putx64,
	.fixmap_map = hyp_fixmap_map,
	.fixmap_unmap = hyp_fixmap_unmap,
	.flush_dcache_to_poc = __kvm_flush_dcache_to_poc,
	.register_host_perm_fault_handler = hyp_register_host_perm_fault_handler,
	.protect_host_page = hyp_protect_host_page,
};

struct pkvm_module *pkvm_module_next_empty(void)
{
	int i;

	for (i = 0; i < MAX_MODULES; i++) {
		if (!modules[i].hyp_text)
			return &modules[i];
	}

	return NULL;
}

int __pkvm_init_module(unsigned long args_hva)
{
	int (*do_module_init)(const struct pkvm_module_ops *ops);
	struct pkvm_el2_module_args *args;
	struct pkvm_module *module;
	int ret;

	args = (struct pkvm_el2_module_args *)kern_hyp_va(args_hva);

	ret = __pkvm_host_donate_hyp(hyp_virt_to_pfn((void *)args), 1);
	if (ret)
		return ret;

	hyp_spin_lock(&modules_lock);

	module = pkvm_module_next_empty();
	if (!module) {
		ret = -ENOMEM;
		goto err_unmap;
	}

	module->id = args->id;
	module->hyp_text = args->hyp_text;
	do_module_init = (void *)((unsigned long)args->hyp_text +
				  (unsigned long)args->hyp_init_offset);

	ret = do_module_init(&module_ops);
	/* init failed... this slot can be reused */
	if (ret)
		module->hyp_text = 0;
err_unmap:
	WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn((void *)args), 1));
	hyp_spin_unlock(&modules_lock);

	return ret;
}
