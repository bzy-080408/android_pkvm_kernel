/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Implementation of the memory encryption/decryption API.
 *
 * Amusingly, no crypto is actually performed. Rather, we call into the
 * hypervisor component of KVM to expose pages selectively to the host
 * for virtio "DMA" operations. In other words, "encrypted" pages are
 * not accessible to the host, whereas "decrypted" pages are.
 *
 * Author: Will Deacon <will@kernel.org>
 */

#include <linux/kernel.h>
#include <linux/mem_encrypt.h>
#include <linux/swiotlb.h>

int set_memory_encrypted(unsigned long addr, int numpages)
{
	/* TODO: unshare the page from the host */
	trace_printk("0x%lx - 0x%lx\n", addr, addr + numpages * PAGE_SIZE);
	dump_stack();
	arm_smccc_1_1_invoke(ARM_SMCCC_DMA_UNSHARE,
			     virt_to_phys((void *)addr),
			     numpages * PAGE_SIZE);
	return 0;
}

int set_memory_decrypted(unsigned long addr, int numpages)
{
	/* TODO: share the page with the host */
	trace_printk("0x%lx - 0x%lx\n", addr, addr + numpages * PAGE_SIZE);
	dump_stack();
	arm_smccc_1_1_invoke(ARM_SMCCC_DMA_SHARE,
			     virt_to_phys((void *)addr),
			     numpages * PAGE_SIZE);
	return 0;
}

bool mem_encrypt_active(void)
{
	/* TODO: Probe from KVM and returned cached result here */
	return true;
}

void __init mem_encrypt_init(void)
{
	swiotlb_update_mem_attributes();
}
