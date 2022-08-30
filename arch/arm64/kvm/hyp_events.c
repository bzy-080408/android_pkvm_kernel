#include <linux/trace_events.h>

#include <asm/kvm_hypevents_defs.h>

#include "hyp_trace.h"

struct hyp_event {
	struct trace_event_call call;
	char name[32];
};

#define HYP_EVENT(__name, __proto, __struct, __assign, __printk)		\
	HYP_EVENT_FORMAT(__name, __struct);					\
	enum print_line_t hyp_event_trace_##__name(struct trace_iterator *iter,	\
					  int flags, struct trace_event *event) \
	{									\
		struct ht_iterator *ht_iter = (struct ht_iterator *)iter;	\
		struct trace_hyp_format_##__name __maybe_unused *__entry =	\
			(struct trace_hyp_format_##__name *)ht_iter->ent;	\
		trace_seq_printf(&ht_iter->seq, __printk);				\
		trace_seq_putc(&ht_iter->seq, '\n');					\
		return TRACE_TYPE_HANDLED;					\
	}
#include <asm/kvm_hypevents.h>

#undef he_field
#define he_field(_type, _item) 						\
	{								\
		.type = #_type, .name = #_item,				\
		.size = sizeof(_type), .align = __alignof__(_type),	\
		.is_signed = is_signed_type(_type),			\
	},
#undef HYP_EVENT
#define HYP_EVENT(__name, __proto, __struct, __assign, __printk)		\
	static struct trace_event_fields hyp_event_fields_##__name[] = {	\
		__struct							\
		{}								\
	};									\

#undef __ARM64_KVM_HYPEVENTS_H_
#include <asm/kvm_hypevents.h>

#undef HYP_EVENT
#define HYP_EVENT(__name, __proto, __struct, __assign, __printk)		\
	static struct trace_event_functions hyp_event_funcs_##__name = {	\
		.trace = &hyp_event_trace_##__name,				\
	};									\
	static struct trace_event_class hyp_event_class_##__name = {		\
		.system		= "nvhe-hypervisor",				\
		.fields_array	= hyp_event_fields_##__name,			\
		.fields		= LIST_HEAD_INIT(hyp_event_class_##__name.fields),\
	};									\
	struct hyp_event __section("_hyp_events") hyp_event_##__name = {	\
		.name = #__name,						\
		.call.class = &hyp_event_class_##__name,			\
		.call.event.funcs = &hyp_event_funcs_##__name,			\
	}

#undef __ARM64_KVM_HYPEVENTS_H_
#include <asm/kvm_hypevents.h>

extern struct hyp_event __start_hyp_events[];
extern struct hyp_event __stop_hyp_events[];

/* hyp_event section used by the hypervisor*/
extern unsigned short __hyp_event_ids_start[];
extern unsigned short __hyp_event_ids_end[];

/*
 * Let's abuse a bit the host tracing... so everything is tied to a trace_array,
 * including events. The hypervisor tracing doesn't declare a trace_array and
 * isn't part of the global one. However, we still would like to have a user
 * interface for our events... so let's just add the hyp events somewhere!
 *
 * TODO: It might not be the best approach. As stated above alternatively, hyp
 * tracing could be:
 *
 *   A. a separated trace_array (i.e. instance) even if it wouldn't make much use
 *   of it.
 *
 *   B. part of the global trace_array with a separated ring_buffer and pipe
 *   interface!
 *
 */
void kvm_hyp_init_events_tracefs(void)
{
	struct hyp_event *event = __start_hyp_events;
	int ret;

	return;

	for (; (unsigned long)event < (unsigned long)__stop_hyp_events; event++) {
		ret = trace_add_event_call(&event->call);
		if (ret)
			pr_warn("Couldn't register event call for %s\n", event->name);
	}
}

/*
 * Register hyp events and write their id into the hyp section _hyp_event_ids.
 */
int kvm_hyp_init_events(void)
{
	struct hyp_event *event = __start_hyp_events;
	unsigned short *hyp_event_id = __hyp_event_ids_start;
	int ret, err = -ENODEV;

	/* TODO: BUILD_BUG nr events host side / hyp side */

	printk("%s: __hyp_event_ids_start=%px", __func__, __hyp_event_ids_start);

	for (; (unsigned long)event < (unsigned long)__stop_hyp_events;
		event++, hyp_event_id++) {
		event->call.name = event->name;
		ret = register_trace_event(&event->call.event);
		if (!ret) {
			pr_warn("Couldn't register trace event for %s\n", event->name);
			continue;
		}

		/*
		 * Both the host and the hypervisor relies on the same hyp event
		 * declarations from kvm_hypevents.h. We have then a 1:1
		 * mapping.
		 */
		*hyp_event_id = ret;

		printk("%s: hyp_event_id@%px=%d", __func__, hyp_event_id, *hyp_event_id);

		err = 0;
	}

	return err;
}
