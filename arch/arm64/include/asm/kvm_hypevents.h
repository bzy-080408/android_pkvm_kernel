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

#endif
