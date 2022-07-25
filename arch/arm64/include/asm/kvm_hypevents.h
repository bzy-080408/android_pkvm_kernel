#ifndef __ARM64_KVM_HYPEVENTS_H_
#define __ARM64_KVM_HYPEVENTS_H_

#ifdef __KVM_NVHE_HYPERVISOR__
#include <nvhe/trace.h>
#else
#include <asm/kvm_hypevents_defs.h>
#endif

/*
 * Hypervisor events definitions.
 */

#ifndef hyp_evt_id
#define hyp_evt_id
enum hyp_evt_id {
	HYP_EVT_ENTER,
	HYP_EVT_EXIT,
	HYP_EVT_POP_MEMCACHE,
	HYP_EVT_PUSH_MEMCACHE,
	HYP_EVT_COALESCED_BLOCK,
	HYP_DO_NOT_PRESS,
	__NUM_HYP_EVENTS,
};
#endif

HYP_EVENT(pop_hyp_memcache,
	HYP_EVT_POP_MEMCACHE,
	HE_PROTO(u64 mc, u64 paddr, u64 nr_pages),
	HE_STRUCT(
		he_field(u64, mc)
		he_field(u64, paddr)
		he_field(u64, nr_pages)
	),
	HE_ASSIGN(
		__entry->mc = mc;
		__entry->paddr = paddr;
		__entry->nr_pages = nr_pages;
	)
);

HYP_EVENT(push_hyp_memcache,
	HYP_EVT_PUSH_MEMCACHE,
	HE_PROTO(u64 mc, u64 paddr, u64 nr_pages),
	HE_STRUCT(
		he_field(u64, mc)
		he_field(u64, paddr)
		he_field(u64, nr_pages)
	),
	HE_ASSIGN(
		__entry->mc = mc;
		__entry->paddr = paddr;
		__entry->nr_pages = nr_pages;
	)
);

HYP_EVENT(hyp_enter,
	HYP_EVT_ENTER,
	HE_PROTO(u64 esr, u64 x0, u32 vmid),
	HE_STRUCT(
		  he_field(u64, esr)
		  he_field(u64, x0)
		  he_field(u32, vmid)
	),
	HE_ASSIGN(
		__entry->esr = esr;
		__entry->x0 = x0;
		__entry->vmid = vmid;
	)
);

HYP_EVENT(hyp_exit,
	HYP_EVT_EXIT,
	HE_PROTO(void),
	HE_STRUCT(
	),
	HE_ASSIGN(
	)
);

HYP_EVENT(hyp_coalesced,
	  HYP_EVT_COALESCED_BLOCK,
	  HE_PROTO(u64 addr, u64 end, u32 level),
	  HE_STRUCT(
		    he_field(u64, addr)
		    he_field(u64, end)
		    he_field(u32, level)
	  ),
	  HE_ASSIGN(
		    __entry->addr = addr;
		    __entry->end  = end;
		    __entry->level = level;
	  )
);
#endif
