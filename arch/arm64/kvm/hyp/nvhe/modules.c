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
#include <nvhe/spinlock.h>
#include <nvhe/trap_handler.h>

#define MAX_MODULES 16

atomic_t num_modules = ATOMIC_INIT(0);
DEFINE_HYP_SPINLOCK(modules_lock);

struct pkvm_module {
	unsigned long id;
	void *hyp_text;
	void *hyp_hva_text;
};

static struct pkvm_module modules[MAX_MODULES];

const struct pkvm_module_ops module_ops = {
	.create_private_mapping = __pkvm_create_private_mapping,
	.register_serial_driver = __pkvm_register_serial_driver,
};

struct pkvm_module *pkvm_module_next_empty(void)
{
	if (atomic_read(&num_modules) >= MAX_MODULES)
		return NULL;

	return &modules[atomic_read(&num_modules)];
}

struct pkvm_module *pkvm_module_find(unsigned long id)
{
	int i;

	/*
	 * num_modules ordered with modules[]. Acquire paired with
	 *  __pkvm_init_module()
	 */
	for (i = 0; i < atomic_read_acquire(&num_modules); i++) {
		if (modules[i].id == id)
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
	module->hyp_hva_text = args->hyp_hva_text;

	do_module_init = (void *)((unsigned long)args->hyp_text +
				  (unsigned long)args->hyp_init_offset);

	ret = do_module_init(&module_ops);
	/*
	 * num_modules ordered with modules[]. Acquire paired with
	 * pkvm_module_find()
	 */
	if (!ret)
		atomic_inc_return_release(&num_modules);

err_unmap:
	WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn((void *)args), 1));
	hyp_spin_unlock(&modules_lock);

	return ret;
}

#define MAX_DYNAMIC_HCALLS 128

atomic_t num_dynamic_hcalls = ATOMIC_INIT(0);
DEFINE_HYP_SPINLOCK(dyn_hcall_lock);

static dyn_hcall_t host_dynamic_hcalls[MAX_DYNAMIC_HCALLS];

int handle_host_dynamic_hcall(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(unsigned long, id, host_ctxt, 0);
	dyn_hcall_t hfn;
	int dyn_id;

	/*
	 * TODO: static key to protect when no dynamic hcall is registered?
	 */

	dyn_id = (int)id - KVM_HOST_SMCCC_ID(0) -
		 __KVM_HOST_SMCCC_FUNC___dynamic_hcalls;
	if (dyn_id < 0)
		return HCALL_UNHANDLED;

	cpu_reg(host_ctxt, 0) = SMCCC_RET_NOT_SUPPORTED;

	/*
	 * Order access to num_dynamic_hcalls and host_dynamic_hcalls. Paired
	 * with __pkvm_register_hcall().
	 */
	if (dyn_id >= atomic_read_acquire(&num_dynamic_hcalls))
		goto end;

	hfn = READ_ONCE(host_dynamic_hcalls[dyn_id]);
	if (!hfn)
		goto end;

	cpu_reg(host_ctxt, 0) = SMCCC_RET_SUCCESS;
	hfn(host_ctxt);
end:
	return HCALL_HANDLED;
}

int __pkvm_register_hcall(unsigned long hfn_kern_va, unsigned long module_id)
{
	struct pkvm_module *mod;
	dyn_hcall_t hfn;
	int reserved_id;

	hyp_spin_lock(&modules_lock);
	mod = pkvm_module_find(module_id);
	hyp_spin_unlock(&modules_lock);
	if (!mod)
		return -ENODEV;

	hfn = (void *)(hfn_kern_va - (unsigned long)mod->hyp_hva_text +
		       (unsigned long)mod->hyp_text);

	hyp_spin_lock(&dyn_hcall_lock);

	reserved_id = atomic_read(&num_dynamic_hcalls);

	if (reserved_id >= MAX_DYNAMIC_HCALLS) {
		hyp_spin_unlock(&dyn_hcall_lock);
		return -ENOMEM;
	}

	WRITE_ONCE(host_dynamic_hcalls[reserved_id], hfn);

	/*
	 * Order access to num_dynamic_hcalls and host_dynamic_hcalls. Paired
	 * with handle_host_dynamic_hcall.
	 */
	atomic_set_release(&num_dynamic_hcalls, reserved_id + 1);

	hyp_spin_unlock(&dyn_hcall_lock);

	return reserved_id + __KVM_HOST_SMCCC_FUNC___dynamic_hcalls;
};
