#ifndef __ARM64_KVM_HYPTRACE_H_
#define __ARM64_KVM_HYPTRACE_H_
#include <linux/ring_buffer_ext.h>

/*
 * Host donations to the hypervisor to store the struct hyp_buffer_page.
 */
struct hyp_buffer_pages_backing {
	unsigned long start;
	size_t size;
};

struct hyp_trace_pack {
	u64					epoch_ns;
	u64					epoch_cyc;
	struct hyp_buffer_pages_backing		backing;
	struct trace_buffer_pack		trace_buffer_pack;

};
#endif
