#ifndef __ARM64_KVM_HYPEVENTS_H_
#define __ARM64_KVM_HYPEVENTS_H_

#ifdef __KVM_NVHE_HYPERVISOR__
#include <nvhe/trace.h>
#endif

/*
 * Hypervisor events definitions.
 */

HYP_EVENT(pop_hyp_memcache,
	HE_PROTO(u64 mc, u64 paddr, u8 nr_pages),
	HE_STRUCT(
		he_field(u64, mc)
		he_field(u64, paddr)
		he_field(u64, nr_pages)
	),
	HE_ASSIGN(
		__entry->mc = mc;
		__entry->paddr = paddr;
		__entry->nr_pages = nr_pages;
	),
	HE_PRINTK("mc=%llu paddr=%llu nr_pages=%llu",
		  __entry->mc, __entry->paddr, __entry->nr_pages)
);

HYP_EVENT(push_hyp_memcache,
	HE_PROTO(u64 mc, u64 paddr, u8 nr_pages),
	HE_STRUCT(
		he_field(u64, mc)
		he_field(u64, paddr)
		he_field(u64, nr_pages)
	),
	HE_ASSIGN(
		__entry->mc = mc;
		__entry->paddr = paddr;
		__entry->nr_pages = nr_pages;
	),
	HE_PRINTK("mc=%llu paddr=%llu nr_pages=%llu",
		  __entry->mc, __entry->paddr, __entry->nr_pages)
);

HYP_EVENT(hyp_enter,
	HE_PROTO(u64 esr, u64 x0, u64 vmid),
	HE_STRUCT(
		  he_field(u64, esr)
		  he_field(u64, x0)
		  he_field(u64, vmid)
	),
	HE_ASSIGN(
		__entry->esr = esr;
		__entry->x0 = x0;
		__entry->vmid = vmid;
	),
	HE_PRINTK("esr=%llx x0=%llx vmid=%llu",
		  __entry->esr, __entry->x0, __entry->vmid)
);

HYP_EVENT(hyp_exit,
	HE_PROTO(void),
	HE_STRUCT(
	),
	HE_ASSIGN(
	),
	HE_PRINTK(" ")
);
#endif
