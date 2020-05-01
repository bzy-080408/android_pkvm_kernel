// SPDX-License-Identifier: GPL-2.0-only
#ifndef __KVM_HYP_MEMORY_H
#define __KVM_HYP_MEMORY_H

#include <linux/types.h>

struct hyp_zone;
struct hyp_page {
	unsigned int order;
	struct hyp_zone *zone;
	int refcount;
	union {
		/* allocated page */
		void *virt;
		/* free page */
		struct list_head node;
	};
	/* Range of 'sibling' pages (donated by the host at the same time) */
	phys_addr_t sibling_range_start;
	phys_addr_t sibling_range_end;
};

extern s64 hyp_physvirt_offset;
extern u64 __hyp_vmemmap;
#define hyp_vmemmap ((struct hyp_page *)__hyp_vmemmap)

/* Page / VA / PA conversion */
#define hyp_virt_to_phys(virt)	((phys_addr_t)(virt) + hyp_physvirt_offset)
#define hyp_phys_to_virt(virt)	(void*)((phys_addr_t)(virt) - hyp_physvirt_offset)
#define __hyp_va		hyp_phys_to_virt
#define __hyp_pa		hyp_virt_to_phys

#define hyp_phys_to_pfn(phys)	((phys) >> PAGE_SHIFT)
#define hyp_phys_to_page(phys)	&hyp_vmemmap[hyp_phys_to_pfn(phys)]
#define hyp_virt_to_page(virt)	hyp_phys_to_page(hyp_virt_to_phys(virt))

#define hyp_page_to_phys(page)  ((phys_addr_t)((page) - hyp_vmemmap) << PAGE_SHIFT)
#define hyp_page_to_virt(page)	__hyp_va(hyp_page_to_phys(page))
#define hyp_page_to_zone(page)	((struct hyp_page*)page)->zone

#define VA_BITS			(CONFIG_ARM64_VA_BITS)

#define __ALIGN_HYP_MASK(x, mask) (((x) + (mask)) & ~(mask))
#define __ALIGN_HYP(x, a) __ALIGN_HYP_MASK(x, (typeof(x))(a) - 1)
#define HYP_ALIGN(x, a) __ALIGN_HYP((x), (a))
#ifndef PAGE_ALIGN
#define PAGE_ALIGN(addr) HYP_ALIGN(addr, PAGE_SIZE)
#endif

#define offset_in_page(p)	((unsigned long)(p) & ~PAGE_MASK)

#endif /* __KVM_HYP_MEMORY_H */
