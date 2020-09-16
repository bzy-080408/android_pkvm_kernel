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
#ifndef __ASM_MEM_ENCRYPT_H
#define __ASM_MEM_ENCRYPT_H

// TODO: Hook this to figure out if we're using this stuff or not/
//void __init mem_encrypt_init(void);

static inline bool mem_encrypt_active(void)
{
	return true;
}

static inline bool force_dma_unencrypted(struct device *dev)
{
	// TODO: only for virtio?
	return true;
}

static inline int set_memory_encrypted(unsigned long addr, int numpages)
{
	// TODO: unshare the page from the host
	return 0;
}

static inline int set_memory_decrypted(unsigned long addr, int numpages)
{
	// TODO: share the page with the host
	return 0;
}
#endif	/* __ASM_MEM_ENCRYPT_H */
