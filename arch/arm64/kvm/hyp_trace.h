#ifndef __ARM64_KVM_HYP_TRACE_H__
#define __ARM64_KVM_HYP_TRACE_H__

#include <linux/workqueue.h>

struct ht_iterator {
	struct ring_buffer_iter *buf_iter;
	struct trace_buffer *trace_buffer;
	struct hyp_entry_hdr *ent;
	struct trace_seq seq;
	u64 ts;
	void *spare;
	size_t copy_leftover;
	size_t ent_size;
	struct delayed_work poke_work;
	unsigned long lost_events;
	int cpu;
};

#ifdef CONFIG_TRACING
int init_hyp_tracefs(void);
#else
int init_hyp_tracefs(void) { return 0; }
#endif
#endif
