#ifndef _UAPI_TRACE_MMAP_H_
#define _UAPI_TRACE_MMAP_H_

struct ring_buffer_meta_page {
	__u64		entries;
	__u64		overrun;
	__u32		pages_touched;
	__u32		reader_page;
	__u32		nr_data_pages;
	__u32		data_page_head;
	__u32		data_pages[];
};

#define TRACE_MMAP_IOCTL_GET_READER_PAGE	_IO('T', 0x1)
#define TRACE_MMAP_IOCTL_UPDATE_META_PAGE	_IO('T', 0x2)

#endif /* _UAPI_TRACE_MMAP_H_ */
