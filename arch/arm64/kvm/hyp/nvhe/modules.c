/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TODO: authorship
 */
#include <asm/kvm_host.h>
#include <asm/kvm_pkvm_module.h>

#include <nvhe/modules.h>
#include <nvhe/mm.h>
#include <nvhe/serial.h>
#include <nvhe/spinlock.h>
#include <nvhe/iommu.h>
#include <nvhe/trap_handler.h>

#define MAX_DYNAMIC_HCALLS 16

atomic_t num_dynamic_hcalls = ATOMIC_INIT(0);
DEFINE_HYP_SPINLOCK(dyn_hcall_lock);

static dyn_hcall_t host_dynamic_hcalls[MAX_DYNAMIC_HCALLS]; /* TODO: hyp_early_alloc_contig on the first registration ? */

int handle_host_dynamic_hcall(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(unsigned long, id, host_ctxt, 0);
	dyn_hcall_t hfn;
	int dyn_id;

	/*
	 * TODO: static key to protect when no dynamic hcall is registered?
	 */

	dyn_id = id - KVM_HOST_SMCCC_ID(0) -
		      __KVM_HOST_SMCCC_FUNC___dynamic_hcalls;
	if (dyn_id < 0)
		return HCALL_UNHANDLED;

	cpu_reg(host_ctxt, 0) = SMCCC_RET_NOT_SUPPORTED;

	if (dyn_id >= atomic_read(&num_dynamic_hcalls))
		goto end;

	hfn = READ_ONCE(host_dynamic_hcalls[dyn_id]);
	if (!hfn)
		goto end;

	cpu_reg(host_ctxt, 0) = SMCCC_RET_SUCCESS;
	hfn(host_ctxt);
end:
	return HCALL_HANDLED;
}

int __pkvm_register_hcall(void *hfn_ptr)
{
	dyn_hcall_t hfn = (dyn_hcall_t)hfn_ptr;
	int reserved_id;

	hyp_spin_lock(&dyn_hcall_lock);

	if (atomic_read(&num_dynamic_hcalls) >= MAX_DYNAMIC_HCALLS) {
		hyp_spin_unlock(&dyn_hcall_lock);
		return -ENOMEM;
	}

	reserved_id = atomic_inc_return(&num_dynamic_hcalls) - 1;
	WRITE_ONCE(host_dynamic_hcalls[reserved_id], hfn);

	hyp_spin_unlock(&dyn_hcall_lock);

	return reserved_id + __KVM_HOST_SMCCC_FUNC___dynamic_hcalls;
};

static phys_addr_t __module_kern_hyp_va(phys_addr_t x){
	return kern_hyp_va(x);
}

const struct pkvm_module_ops module_ops = {
	.create_private_mapping = __pkvm_create_private_mapping,
	.register_serial_driver = __pkvm_register_serial_driver,
	.pkvm_host_donate_hyp = __pkvm_host_donate_hyp,
	.pkvm_hyp_donate_host = __pkvm_hyp_donate_host,
	.register_serial_driver = __pkvm_register_serial_driver,
	.register_iommu_driver = __pkvm_register_iommu_driver,
	.memcpy = memcpy,
	.memset = memset,
	.dcache_clean_inval_poc = dcache_clean_inval_poc,
	.hyp_puts = hyp_puts,
	.module_hyp_pa = hyp_virt_to_phys,
	.module_kern_hyp_va = __module_kern_hyp_va,

};

int __pkvm_init_module(void *module_init)
{
	int (*do_module_init)(const struct pkvm_module_ops *ops) = module_init;
	int ret;

	ret = do_module_init(&module_ops);
	if (!ret)
		hyp_puts("Module loaded at EL2!");
	else
		hyp_puts("Failed to load EL2 module");

	return ret;
}
