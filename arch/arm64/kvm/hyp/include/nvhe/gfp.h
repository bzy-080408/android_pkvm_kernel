// SPDX-License-Identifier: GPL-2.0-only
#ifndef __KVM_HYP_GFP_H
#define __KVM_HYP_GFP_H

#include <linux/list.h> /* XXX - use hyp version instead */

#include <nvhe/memory.h>
#include <nvhe/spinlock.h>

#define HYP_MAX_ORDER	11U
#define HYP_NO_ORDER	UINT_MAX

struct hyp_zone {
	nvhe_spinlock_t lock;
	struct list_head free_area[HYP_MAX_ORDER + 1];
};

// GFP flags
#define HYP_GFP_NONE	0
#define HYP_GFP_ZERO	1

/* Allocation */
void *hyp_alloc_pages(struct hyp_zone *zone, gfp_t mask, unsigned int order);
#define hyp_alloc_page(zone, mask) hyp_alloc_pages((zone), (mask), 0)
#define hyp_alloc_zeroed_page(zone) hyp_alloc_page((zone), HYP_GFP_ZERO)

void hyp_get_page(struct hyp_page *p);
void hyp_put_page(struct hyp_page *p);

static inline void hyp_free_page(unsigned long addr)
{
	hyp_put_page(hyp_virt_to_page(addr));
}

static inline int hyp_page_count(struct hyp_page *p)
{
	return p->refcount;
}

#define hyp_get_page hyp_get_page
#define hyp_put_page hyp_put_page
#define hyp_free_page hyp_free_page
#define hyp_page_count hyp_page_count

extern struct hyp_zone host_zone;
#define hyp_host_get_zeroed_pages(order) hyp_alloc_pages(&host_zone, HYP_GFP_ZERO, (order))

/* Used pages cannot be freed */
int hyp_zone_extend_used(struct hyp_zone *zone, phys_addr_t phys,
			 unsigned int nr_pages, unsigned int used_pages);

static inline int hyp_zone_extend(struct hyp_zone *zone, phys_addr_t phys,
				  unsigned int nr_pages)
{
	return hyp_zone_extend_used(zone, phys, nr_pages, 0);
}

void hyp_zone_init(struct hyp_zone *zone);
#endif /* __KVM_HYP_GFP_H */
