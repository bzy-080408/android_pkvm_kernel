#ifndef __ARM64_KVM_HYPEVENTS_DEFS_H
#define __ARM64_KVM_HYPEVENTS_DEFS_H

/*
 * Hyp events definitions common to the hyp and the host
 */
#define HYP_EVENT_FORMAT(__name, __struct)	\
	struct trace_hyp_format_##__name {	\
		__struct			\
	};

#define HE_PROTO(args...)	args
#define HE_STRUCT(args...)	args
#define HE_ASSIGN(args...)	args

#define he_field(type, item)	type item;

#ifndef __KVM_NVHE_HYPERVISOR__
#define HYP_EVENT(__name, __id, __proto, __struct, __assign) \
	HYP_EVENT_FORMAT(__name, __struct)
#endif

#endif
