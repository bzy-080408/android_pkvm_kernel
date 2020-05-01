// SPDX-License-Identifier: GPL-2.0-only
#ifndef __KVM_HYP_EARLY_ALLOC_H
#define __KVM_HYP_EARLY_ALLOC_H

#include <nvhe/memory.h>

static inline void hyp_free_page(unsigned long addr) {}
static inline void hyp_get_page(void *page) {}
static inline void hyp_put_page(void *page) {}
static inline int hyp_page_count(void *page) { return 0; }
#define hyp_free_page hyp_free_page
#define hyp_get_page hyp_get_page
#define hyp_put_page hyp_put_page
#define hyp_page_count hyp_page_count
#define hyp_host_get_zeroed_pages hyp_early_alloc_pages

void hyp_early_alloc_init(unsigned long phys, unsigned long virt,
			  unsigned long size);

void *hyp_early_alloc_pages(int order);
unsigned long hyp_early_alloc_nr_pages(void);

#endif /* __KVM_HYP_EARLY_ALLOC_H */
