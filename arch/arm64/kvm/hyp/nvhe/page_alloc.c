// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google, inc
 * Author: Quentin Perret <qperret@google.com>
 */

#include <asm/kvm_hyp.h>
#include <nvhe/gfp.h>

/*
 * Example buddy-tree for a 4-pages physically contiguous zone:
 *
 *                 o : Page 3
 *                /
 *               o-o : Page 2
 *              /
 *             /   o : Page 1
 *            /   /
 *           o---o-o : Page 0
 *    Order  2   1 0
 *
 * Example of requests on this zone:
 *   __find_buddy(zone, page 0, order 0) => page 1
 *   __find_buddy(zone, page 0, order 1) => page 2
 *   __find_buddy(zone, page 1, order 0) => page 0
 *   __find_buddy(zone, page 2, order 0) => page 3
 */
static struct hyp_page * __find_buddy(struct hyp_zone *zone,
						 struct hyp_page *p,
						 unsigned int order)
{
	phys_addr_t addr = hyp_page_to_phys(p);

	addr ^= (PAGE_SIZE << order);
	if (addr < p->sibling_range_start || addr >= p->sibling_range_end)
		return NULL;

	return hyp_phys_to_page(addr);
}

static void __hyp_attach_page(struct hyp_zone *zone,
					 struct hyp_page *p)
{
	unsigned int order = p->order;
	struct hyp_page *buddy;

	p->order = HYP_NO_ORDER;
	for (;order < HYP_MAX_ORDER; order++) {
		/* Nothing to do if the buddy isn't in a free-list */
		buddy = __find_buddy(zone, p, order);
		if (!buddy || list_empty(&buddy->node))
			break;

		/* Otherwise, coalesce the buddies and go one level up */
		list_del_init(&buddy->node);
		buddy->order = HYP_NO_ORDER;
		p = (p < buddy) ? p : buddy;
	}

	p->order = order;
	list_add_tail(&p->node, &zone->free_area[order]);
}

void hyp_put_page(struct hyp_page *p)
{
	struct hyp_zone *zone = hyp_page_to_zone(p);

	nvhe_spin_lock(&zone->lock); /* XXX */
	p->refcount--;
	if (!p->refcount)
		__hyp_attach_page(zone, p);
	nvhe_spin_unlock(&zone->lock);
}

void hyp_get_page(struct hyp_page *p)
{
	struct hyp_zone *zone = hyp_page_to_zone(p);

	nvhe_spin_lock(&zone->lock); /* XXX */
	p->refcount++;
	nvhe_spin_unlock(&zone->lock);
}

/* Extract a page from the buddy tree, at a specific order */
static struct hyp_page * __hyp_extract_page(struct hyp_zone *zone,
						       struct hyp_page *p,
						       unsigned int order)
{
	struct hyp_page *buddy;

	if (p->order == HYP_NO_ORDER || p->order < order)
		return NULL;

	list_del_init(&p->node);

	/* Split the page in two until reaching the requested order */
	while (p->order > order) {
		p->order--;
		buddy = __find_buddy(zone, p, p->order);
		buddy->order = p->order;
		list_add_tail(&buddy->node, &zone->free_area[buddy->order]);
	}

	p->refcount = 1;

	return p;
}

extern void clear_page(void *to);
static void clear_hyp_page(struct hyp_page *p)
{
	unsigned long i;

	for (i = 0; i < (1 << p->order); i++)
		clear_page(hyp_page_to_virt(p) + (i << PAGE_SHIFT));
}

static void * __hyp_alloc_pages(struct hyp_zone *zone, gfp_t mask,
					   unsigned int order)
{
	unsigned int i = order;
	struct hyp_page *p;

	/* Look for a high-enough-order page */
	while (i <= HYP_MAX_ORDER && list_empty(&zone->free_area[i]))
		i++;
	if (i > HYP_MAX_ORDER)
		return NULL;

	/* Extract it from the tree at the right order */
	p = list_first_entry(&zone->free_area[i], struct hyp_page, node);
	p = __hyp_extract_page(zone, p, order);

	if (mask & HYP_GFP_ZERO)
		clear_hyp_page(p);

	return p;
}

void * hyp_alloc_pages(struct hyp_zone *zone, gfp_t mask,
				  unsigned int order)
{
	struct hyp_page *p;

	nvhe_spin_lock(&zone->lock);
	p = __hyp_alloc_pages(zone, mask, order);
	nvhe_spin_unlock(&zone->lock);

	return p ? hyp_page_to_virt(p) : NULL;
}

/* hyp_vmemmap must be backed beforehand */
int hyp_zone_extend_used(struct hyp_zone *zone, phys_addr_t phys,
				    unsigned int nr_pages,
				    unsigned int used_pages)
{
	phys_addr_t range_end = phys + (nr_pages << PAGE_SHIFT);
	struct hyp_page *p;
	int i;

	if (phys % PAGE_SIZE)
		return -EINVAL;

	nvhe_spin_lock(&zone->lock);

	/* Init the vmemmap portion - XXX can be done lazily ? */
	p = hyp_phys_to_page(phys);
	for (i = 0; i < nr_pages; i++, p++) {
		p->order = 0;
		p->zone = zone;
		p->refcount = 0;
		INIT_LIST_HEAD(&p->node);
		p->sibling_range_start = phys;
		p->sibling_range_end = range_end;
	}

	/* Attach the unused pages to the buddt tree - XXX optimize ? */
	p = hyp_phys_to_page(phys + (used_pages << PAGE_SHIFT));
	for (i = used_pages; i < nr_pages; i++, p++)
		__hyp_attach_page(zone, p);

	nvhe_spin_unlock(&zone->lock);

	return 0;
}

void hyp_zone_init(struct hyp_zone *zone)
{
	unsigned int i;

	nvhe_spin_lock_init(&zone->lock);
	for (i = 0; i <= HYP_MAX_ORDER; i++)
		INIT_LIST_HEAD(&zone->free_area[i]);
}
