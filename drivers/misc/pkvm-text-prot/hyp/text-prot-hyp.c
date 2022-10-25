#include <asm/kvm_hyp.h>
#include <asm/kvm_pkvm_module.h>
#include <asm/kvm_pgtable.h>

phys_addr_t text_start, text_end;

static const struct pkvm_module_ops *ops;

static bool can_handle_fault(u64 esr)
{
	u32 len = BIT((esr & ESR_ELx_SAS) >> ESR_ELx_SAS_SHIFT);

	/*
	 * This should only be used because of kernel text patching. So we can
	 * simplify the hanlding by making a few assumptions:
	 *   - only 32bit-wide accesses are supported (AARCH64_INSN_SIZE)
	 *   - only write faults (which implies dabt)
	 *   - no atomic or release semantics
	 *   - no cache maintenance
	 */
	if (!(esr & ESR_ELx_ISV))
		return false;
	if (len != AARCH64_INSN_SIZE)
		return false;
	if (ESR_ELx_EC(esr) != ESR_ELx_EC_DABT_LOW)
		return false;
	if (!(esr & ESR_ELx_WNR))
		return false;
	if (esr & ESR_ELx_AR)
		return false;
	return true;
}

static int text_perm_fault_cb(struct kvm_cpu_context *host_ctxt, u64 esr, u64 addr)
{
	int rd = (esr & ESR_ELx_SRT_MASK) >> ESR_ELx_SRT_SHIFT;
	void *ptr;

	if (!can_handle_fault(esr))
		return -EINVAL;

	/*
	 * CMOs should have been issued before the fixmap_unmap() call below,
	 * so just skip the one issued by the kernel.
	 */
	if (esr & ESR_ELx_CM) {
		ops->putx64(0xdeadbeef);
		goto skip;
	}

	ptr = ops->fixmap_map(addr);
	if (!ptr)
		return -ENOMEM;
	WRITE_ONCE(*((u32 *)ptr), (u32)host_ctxt->regs.regs[rd]);
	ops->flush_dcache_to_poc(ptr, AARCH64_INSN_SIZE);
	ops->fixmap_unmap();
	ops->putx64(addr);

skip:
	write_sysreg_el2(read_sysreg_el2(SYS_ELR) + 4, SYS_ELR);
	return 0;
}

#define PKVM_PROT_RX (KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_X)
int hyp_init(const struct pkvm_module_ops *__ops)
{
	phys_addr_t addr;
	int ret;

	ops = __ops;

	ret = ops->register_host_perm_fault_handler(text_perm_fault_cb);
	if (ret)
		return ret;

	/*
	 * Ignore return value of protect_host_page() as it is expected to fail
	 * for some regions, e.g. the hypervisor text sections.
	 */
	for (addr = text_start; addr < text_end; addr += PAGE_SIZE) {
		ret = ops->protect_host_page(addr >> PAGE_SHIFT, PKVM_PROT_RX);
	}

	return 0;
}
