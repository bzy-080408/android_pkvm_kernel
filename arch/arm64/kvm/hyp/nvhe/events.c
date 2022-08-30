#include <nvhe/trace.h>

#undef HYP_EVENT
#define HYP_EVENT(__name, __proto, __struct, __assign, __printk)	\
	unsigned short hyp_event_id_##__name __section("_hyp_event_ids");

#include <asm/kvm_hypevents.h>
