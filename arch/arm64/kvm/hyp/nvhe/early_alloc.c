// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google, inc
 * Author: Quentin Perret <qperret@google.com>
 */

#include <asm/page-def.h>
#include <nvhe/memory.h>

static unsigned long __base_phys;
static unsigned long __base_virt;
static unsigned long __end_virt;
static unsigned long __cur_virt;

void hyp_early_alloc_init(unsigned long phys, unsigned long virt,
			  unsigned long size)
{
	__base_phys = phys;
	__base_virt = virt;
	__end_virt = virt + size;
	__cur_virt = virt;
}

extern void clear_page(void *to);
void * hyp_early_alloc_pages(int order)
{
	unsigned long i, ret = __cur_virt;

	__cur_virt += (PAGE_SIZE << order);
	if (__cur_virt > __end_virt) {
		__cur_virt = ret;
		return NULL;
	}

	for (i = 0; i < (1 << order); i++)
		clear_page((void*)ret + (i << PAGE_SHIFT));

	return (void *)ret;
}

unsigned long hyp_early_alloc_nr_pages(void)
{
	return (__cur_virt - __base_virt) >> PAGE_SHIFT;
}
