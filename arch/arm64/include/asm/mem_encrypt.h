/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_MEM_ENCRYPT_H
#define __ASM_MEM_ENCRYPT_H

#include <linux/device.h>

bool mem_encrypt_active(void);
int set_memory_encrypted(unsigned long addr, int numpages);
int set_memory_decrypted(unsigned long addr, int numpages);

static inline bool force_dma_unencrypted(struct device *dev)
{
	// TODO: only for virtio?
	return true;
}

#endif	/* __ASM_MEM_ENCRYPT_H */
