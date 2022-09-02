#include <linux/tracefs.h>
#include <linux/trace_events.h>

#include <asm/kvm_host.h>
#include <asm/kvm_hypevents_defs.h>

#include "hyp_trace.h"

struct hyp_event {
	struct trace_event_call *call;
	char name[32];
	bool *enabled;
};

#define HYP_EVENT(__name, __proto, __struct, __assign, __printk)		\
	HYP_EVENT_FORMAT(__name, __struct);					\
	enum print_line_t hyp_event_trace_##__name(struct trace_iterator *iter,	\
					  int flags, struct trace_event *event) \
	{									\
		struct ht_iterator *ht_iter = (struct ht_iterator *)iter;	\
		struct trace_hyp_format_##__name __maybe_unused *__entry =	\
			(struct trace_hyp_format_##__name *)ht_iter->ent;	\
		trace_seq_puts(&ht_iter->seq, #__name);				\
		trace_seq_putc(&ht_iter->seq, ' ');				\
		trace_seq_printf(&ht_iter->seq, __printk);			\
		trace_seq_putc(&ht_iter->seq, '\n');				\
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
	static struct trace_event_call hyp_event_call_##__name = {		\
		.class = &hyp_event_class_##__name,				\
		.event.funcs = &hyp_event_funcs_##__name,			\
	};									\
	static bool hyp_event_enabled_##__name = false;				\
	struct hyp_event __section("_hyp_events") hyp_event_##__name = {	\
		.name = #__name,						\
		.call = &hyp_event_call_##__name,				\
		.enabled = &hyp_event_enabled_##__name,				\
	}

#undef __ARM64_KVM_HYPEVENTS_H_
#include <asm/kvm_hypevents.h>

extern struct hyp_event __start_hyp_events[];
extern struct hyp_event __stop_hyp_events[];

/* hyp_event section used by the hypervisor */
extern struct hyp_event_id __hyp_event_ids_start[];
extern struct hyp_event_id __hyp_event_ids_end[];

static ssize_t
hyp_event_write(struct file *filp, const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	struct hyp_event *evt = (struct hyp_event *)((struct seq_file *)filp->private_data)->private;
	unsigned short id = evt->call->event.type;
	bool enabling;
	int ret;
	char c;

	if (cnt != 2)
		return -EINVAL;

	if (get_user(c, ubuf))
		return -EFAULT;

	switch (c) {
	case '1':
		enabling = true;
		break;
	case '0':
		enabling = false;
		break;
	default:
		return -EINVAL;
	}

	if (enabling != *evt->enabled) {
		ret = kvm_call_hyp_nvhe(__pkvm_enable_event, id, enabling);
		if (ret)
			return ret;
	}

	*evt->enabled = enabling;

	return cnt;
}

static int hyp_event_show(struct seq_file *m, void *v)
{
	struct hyp_event *evt = (struct hyp_event *)m->private;

	/* lock ?? Ain't no time for that ! */
	seq_printf(m, "%d\n", *evt->enabled);

	return 0;
}

static int hyp_event_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, hyp_event_show, inode->i_private);
}

static const struct file_operations hyp_event_fops = {
	.open		= hyp_event_open,
	.write		= hyp_event_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void kvm_hyp_init_events_tracefs(struct dentry *parent)
{
	struct hyp_event *event = __start_hyp_events;
	struct dentry *d;

	parent = tracefs_create_dir("events", parent);
	if (!parent) {
		pr_err("Failed to create tracefs folder for hyp events\n");
		return;
	}

	for (; (unsigned long)event < (unsigned long)__stop_hyp_events; event++) {
		d = tracefs_create_file(event->name, 0700, parent, (void *)event,
					&hyp_event_fops);
		if (!d)
			pr_err("Failed to create event folder for %s\n", event->name);
	}
}

/*
 * Register hyp events and write their id into the hyp section _hyp_event_ids.
 */
int kvm_hyp_init_events(void)
{
	struct hyp_event *event = __start_hyp_events;
	struct hyp_event_id *hyp_event_id = __hyp_event_ids_start;
	int ret, err = -ENODEV;

	/* TODO: BUILD_BUG nr events host side / hyp side */

	for (; (unsigned long)event < (unsigned long)__stop_hyp_events;
		event++, hyp_event_id++) {
		event->call->name = event->name;
		ret = register_trace_event(&event->call->event);
		if (!ret) {
			pr_warn("Couldn't register trace event for %s\n", event->name);
			continue;
		}

		/*
		 * Both the host and the hypervisor relies on the same hyp event
		 * declarations from kvm_hypevents.h. We have then a 1:1
		 * mapping.
		 */
		hyp_event_id->id = ret;

		printk("%s: hyp_event_id@%px=%d", __func__, hyp_event_id, hyp_event_id->id);

		err = 0;
	}

	return err;
}
