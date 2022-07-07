#ifndef __ARM64_KVM_HYPTRACE_H_
#define __ARM64_KVM_HYPTRACE_H_

#include <linux/cache.h>
#include <linux/threads.h>

#include <asm/page.h>
#include <asm/div64.h>

#define HYP_TRACE_EVT_ARG_SIZE 6

struct hyp_trace_evt_args {
	u64 args[HYP_TRACE_EVT_ARG_SIZE];
};

struct hyp_trace_evt {
	int id;
	u64 timestamp;
	struct hyp_trace_evt_args args;
};

struct hyp_trace_rb_hdr {
	atomic_t write_idx;
	int order;
};

struct hyp_trace_rb {
	struct hyp_trace_rb_hdr hdr;
	struct hyp_trace_evt events[] ____cacheline_aligned;
};

/*
 * Arguments used to create a per-CPU hyp_trace_rb in hypervisor.
 */
struct hyp_trace_rb_args {
	unsigned long kern_va[NR_CPUS];
	int order[NR_CPUS];
	u64 events;
};

static inline u64 __hyp_trace_rb_max_entries(struct hyp_trace_rb *rb)
{
	size_t hdr_size = L1_CACHE_ALIGN(sizeof(struct hyp_trace_rb_hdr));
	unsigned int nr_entries = (PAGE_SIZE << rb->hdr.order) - hdr_size;

	do_div(nr_entries, sizeof(struct hyp_trace_evt));

	return nr_entries;
}

static inline unsigned int __hyp_trace_rb_next_idx(struct hyp_trace_rb *rb)
{
	return atomic_read(&rb->hdr.write_idx) % __hyp_trace_rb_max_entries(rb);
}

#endif
