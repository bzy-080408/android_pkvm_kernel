#include <nvhe/trace.h>

extern struct hyp_event_id __hyp_event_ids_start[];
extern struct hyp_event_id __hyp_event_ids_end[];

#undef HYP_EVENT
#define HYP_EVENT(__name, __proto, __struct, __assign, __printk)	\
	DEFINE_STATIC_KEY_FALSE(__name##_enabled);			\
	struct hyp_event_id hyp_event_id_##__name __section("_hyp_event_ids") = {	\
		.data = (void *)&__name##_enabled,			\
	}

#include <asm/kvm_hypevents.h>

int __pkvm_enable_event(unsigned short id, bool enable)
{
	struct hyp_event_id *event_id = __hyp_event_ids_start;
	struct static_key_false *enable_key;

	for (; (unsigned long)event_id < (unsigned long)__hyp_event_ids_end;
	     event_id++) {
		if (event_id->id != id)
			continue;

		enable_key = (struct static_key_false *)event_id->data;

		if (enable)
			static_branch_enable(enable_key);
		else
			static_branch_disable(enable_key);

		return 0;
	}

	return -EINVAL;
}
