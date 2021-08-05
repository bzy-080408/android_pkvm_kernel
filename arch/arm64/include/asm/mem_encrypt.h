/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_MEM_ENCRYPT_H
#define __ASM_MEM_ENCRYPT_H

int set_memory_encrypted(unsigned long addr, int numpages);
int set_memory_decrypted(unsigned long addr, int numpages);

#endif	/* __ASM_MEM_ENCRYPT_H */
