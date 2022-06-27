#ifndef __ARM64_KVM_HYPEVENTS_H_
#define __ARM64_KVM_HYPEVENTS_H_

#ifdef __KVM_NVHE_HYPERVISOR__
#include <nvhe/trace.h>
#else
#include <asm/kvm_hypevents_defs.h>
#define HYP_EVENT(__name, __id, __proto, __struct, __assign) \
	HYP_EVENT_FORMAT(__name, __struct)
#endif

/*
 * Hypervisor events definitions.
 */

enum hyp_evt_id {
	HYP_EVT_ENTER,
	HYP_EVT_EXIT,
};

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
)

HYP_EVENT(hyp_exit,
	HYP_EVT_EXIT,
	/* TODO: Fix macro to avoid "unused" */
	HE_PROTO(u8 unused),
	HE_STRUCT(
		he_field(u8, unused)
	),
	HE_ASSIGN(
		__entry->unused = unused;
	)
)
#endif
