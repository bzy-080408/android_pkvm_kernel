// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 */

#include <linux/arm-smccc.h>
#include <linux/arm_ffa.h>
#include <nvhe/ffa.h>
#include <nvhe/mem_protect.h>
#include <nvhe/memory.h>
#include <nvhe/trap_handler.h>

/* "ID value 0 must be returned at the Non-secure physical FF-A instance" */
#define HOST_FFA_ID	0

static struct kvm_ffa_buffers ffa_buffers;

static void ffa_to_smccc_error(struct arm_smccc_res *res, u64 errno)
{
	*res = (struct arm_smccc_res) {
		.a0	= FFA_ERROR,
		.a2	= errno,
	};
}

/*
 * FFA_RET_SUCCESS may return function specific results in w2/x2-w7/x7.
 * So far we only need w2/x2.
 */
static void ffa_to_smccc_prop_res(struct arm_smccc_res *res, int ret, u64 x2)
{
	if (ret == FFA_RET_SUCCESS)
		*res = (struct arm_smccc_res) { .a0 = FFA_SUCCESS,
						.a2 = x2 };
	else
		ffa_to_smccc_error(res, ret);
}

static void ffa_to_smccc_res(struct arm_smccc_res *res, int ret)
{
	ffa_to_smccc_prop_res(res, ret, 0);
}

static void ffa_set_retval(struct kvm_cpu_context *ctxt,
			   struct arm_smccc_res *res)
{
	cpu_reg(ctxt, 0) = res->a0;
	cpu_reg(ctxt, 1) = res->a1;
	cpu_reg(ctxt, 2) = res->a2;
	cpu_reg(ctxt, 3) = res->a3;
}

static bool is_ffa_call(u64 func_id)
{
	return ARM_SMCCC_IS_FAST_CALL(func_id) &&
	       ARM_SMCCC_OWNER_NUM(func_id) == ARM_SMCCC_OWNER_STANDARD &&
	       ARM_SMCCC_FUNC_NUM(func_id) >= FFA_MIN_FUNC_NUM &&
	       ARM_SMCCC_FUNC_NUM(func_id) <= FFA_MAX_FUNC_NUM;
}

static int spmd_map_ffa_buffers(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(FFA_FN64_RXTX_MAP,
			  hyp_virt_to_phys(ffa_buffers.tx),
			  hyp_virt_to_phys(ffa_buffers.rx),
			  PAGE_SIZE / FFA_PAGE_SIZE,
			  0, 0, 0, 0,
			  &res);

	return res.a0 == FFA_SUCCESS ? FFA_RET_SUCCESS : res.a2;
}

static int spmd_unmap_ffa_buffers(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_smc(FFA_RXTX_UNMAP,
			  HOST_FFA_ID,
			  0, 0, 0, 0, 0, 0,
			  &res);

	return res.a0 == FFA_SUCCESS ? FFA_RET_SUCCESS : res.a2;
}

static void spmd_mem_frag_tx(struct arm_smccc_res *res, u32 handle_lo,
			     u32 handle_hi, u32 fraglen, u32 endpoint_id)
{
	arm_smccc_1_1_smc(FFA_MEM_FRAG_TX,
			  handle_lo, handle_hi, fraglen, endpoint_id,
			  0, 0, 0,
			  res);
}

static void spmd_mem_frag_rx(struct arm_smccc_res *res, u32 handle_lo,
			     u32 handle_hi, u32 fragoff)
{
	arm_smccc_1_1_smc(FFA_MEM_FRAG_RX,
			  handle_lo, handle_hi, fragoff,
			  0, 0, 0, 0,
			  res);
}

static void spmd_mem_share(struct arm_smccc_res *res, u32 len, u32 fraglen)
{
	arm_smccc_1_1_smc(FFA_FN64_MEM_SHARE,
			  len, fraglen,
			  0, 0, 0, 0, 0,
			  res);
}

static void spmd_mem_reclaim(struct arm_smccc_res *res, u32 handle_lo,
			     u32 handle_hi, u32 flags)
{
	arm_smccc_1_1_smc(FFA_MEM_RECLAIM,
			  handle_lo, handle_hi, flags,
			  0, 0, 0, 0,
			  res);
}

static void spmd_retrieve_req(struct arm_smccc_res *res, u32 len)
{
	arm_smccc_1_1_smc(FFA_FN64_MEM_RETRIEVE_REQ,
			  len, len,
			  0, 0, 0, 0, 0,
			  res);
}

static void do_ffa_rxtx_map(struct arm_smccc_res *res,
			    struct kvm_cpu_context *ctxt)
{
	DECLARE_REG(phys_addr_t, tx, ctxt, 1);
	DECLARE_REG(phys_addr_t, rx, ctxt, 2);
	DECLARE_REG(u32, npages, ctxt, 3);
	int ret = 0;

	if (npages != PAGE_SIZE / FFA_PAGE_SIZE) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out;
	}

	if (!PAGE_ALIGNED(tx) || !PAGE_ALIGNED(rx)) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out;
	}

	hyp_spin_lock(&host_kvm.ffa.lock);
	if (host_kvm.ffa.tx) {
		ret = FFA_RET_DENIED;
		goto out_unlock;
	}

	ret = spmd_map_ffa_buffers();
	if (ret)
		goto out_unlock;

	ret = __pkvm_host_share_hyp(hyp_phys_to_pfn(tx));
	if (ret) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto err_unmap;
	}

	ret = __pkvm_host_share_hyp(hyp_phys_to_pfn(rx));
	if (ret) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto err_unshare_tx;
	}

	host_kvm.ffa.tx = hyp_phys_to_virt(tx);
	host_kvm.ffa.rx = hyp_phys_to_virt(rx);

out_unlock:
	hyp_spin_unlock(&host_kvm.ffa.lock);
out:
	ffa_to_smccc_res(res, ret);
	return;

err_unshare_tx:
	__pkvm_host_unshare_hyp(hyp_phys_to_pfn(tx));
err_unmap:
	spmd_unmap_ffa_buffers();
	goto out_unlock;
}

static void do_ffa_rxtx_unmap(struct arm_smccc_res *res,
			      struct kvm_cpu_context *ctxt)
{
	DECLARE_REG(u32, id, ctxt, 1);
	int ret = 0;

	if (id != HOST_FFA_ID) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out;
	}

	hyp_spin_lock(&host_kvm.ffa.lock);
	if (!host_kvm.ffa.tx) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	WARN_ON(__pkvm_host_unshare_hyp(hyp_virt_to_pfn(host_kvm.ffa.tx)));
	host_kvm.ffa.tx = NULL;

	WARN_ON(__pkvm_host_unshare_hyp(hyp_virt_to_pfn(host_kvm.ffa.rx)));
	host_kvm.ffa.rx = NULL;

	spmd_unmap_ffa_buffers();

out_unlock:
	hyp_spin_unlock(&host_kvm.ffa.lock);
out:
	ffa_to_smccc_res(res, ret);
}

static u32 __ffa_host_share_ranges(struct ffa_mem_region_addr_range *ranges,
				   u32 nranges)
{
	u32 i;

	for (i = 0; i < nranges; ++i) {
		struct ffa_mem_region_addr_range *range = &ranges[i];
		u64 npages = (range->pg_cnt * FFA_PAGE_SIZE) / PAGE_SIZE;
		u64 pfn = hyp_phys_to_pfn(range->address);

		if (__pkvm_host_share_ffa(pfn, npages))
			break;
	}

	return i;
}

static u32 __ffa_host_unshare_ranges(struct ffa_mem_region_addr_range *ranges,
				     u32 nranges)
{
	u32 i;

	for (i = 0; i < nranges; ++i) {
		struct ffa_mem_region_addr_range *range = &ranges[i];
		u64 npages = (range->pg_cnt * FFA_PAGE_SIZE) / PAGE_SIZE;
		u64 pfn = hyp_phys_to_pfn(range->address);

		if (__pkvm_host_unshare_ffa(pfn, npages))
			break;
	}

	return i;
}

static int ffa_host_share_ranges(struct ffa_mem_region_addr_range *ranges,
				 u32 nranges)
{
	u32 nshared = __ffa_host_share_ranges(ranges, nranges);
	int ret = 0;

	if (nshared != nranges) {
		WARN_ON(__ffa_host_unshare_ranges(ranges, nshared));
		ret = FFA_RET_DENIED;
	}

	return ret;
}

static int ffa_host_unshare_ranges(struct ffa_mem_region_addr_range *ranges,
				   u32 nranges)
{
	u32 nunshared = __ffa_host_unshare_ranges(ranges, nranges);
	int ret = 0;

	if (nunshared != nranges) {
		WARN_ON(__ffa_host_share_ranges(ranges, nunshared));
		ret = FFA_RET_DENIED;
	}

	return ret;
}

static void do_ffa_mem_frag_tx(struct arm_smccc_res *res,
			       struct kvm_cpu_context *ctxt)
{
	DECLARE_REG(u32, handle_lo, ctxt, 1);
	DECLARE_REG(u32, handle_hi, ctxt, 2);
	DECLARE_REG(u32, fraglen, ctxt, 3);
	DECLARE_REG(u32, endpoint_id, ctxt, 4);
	struct ffa_mem_region_addr_range *buf;
	int ret = FFA_RET_INVALID_PARAMETERS;
	u32 nr_ranges;

	if (fraglen > PAGE_SIZE || fraglen % sizeof(*buf))
		goto out;

	hyp_spin_lock(&host_kvm.ffa.lock);
	if (!host_kvm.ffa.tx)
		goto out_unlock;

	buf = ffa_buffers.tx;
	memcpy(buf, host_kvm.ffa.tx, fraglen);
	nr_ranges = fraglen / sizeof(*buf);

	ret = ffa_host_share_ranges(buf, nr_ranges);
	if (ret)
		goto out_unlock;

	spmd_mem_frag_tx(res, handle_lo, handle_hi, fraglen, endpoint_id);
	if (res->a0 != FFA_SUCCESS && res->a0 != FFA_MEM_FRAG_RX)
		WARN_ON(ffa_host_unshare_ranges(buf, nr_ranges));

out_unlock:
	hyp_spin_unlock(&host_kvm.ffa.lock);
out:
	if (ret)
		ffa_to_smccc_res(res, ret);

	/*
	 * If for any reason this did not succeed, we're in trouble as we have
	 * now lost the content of the previous fragments and we can't rollback
	 * the host stage-2 changes. The pages previously marked as shared will
	 * remain stuck in that state forever, hence preventing the host from
	 * sharing/donating them again and may possibly lead to subsequent
	 * failures, but this will not compromise confidentiality.
	 */
	return;
}

static void do_ffa_mem_share(struct arm_smccc_res *res,
			     struct kvm_cpu_context *ctxt)
{
	DECLARE_REG(u32, len, ctxt, 1);
	DECLARE_REG(u32, fraglen, ctxt, 2);
	DECLARE_REG(u64, addr_mbz, ctxt, 3);
	DECLARE_REG(u32, npages_mbz, ctxt, 4);
	struct ffa_composite_mem_region *reg;
	u32 offset, nr_ranges, expected;
	struct ffa_mem_region *buf;
	int ret = 0;

	if (addr_mbz || npages_mbz || fraglen > len || fraglen > PAGE_SIZE) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out;
	}

	if (fraglen < sizeof(struct ffa_mem_region) +
		      sizeof(struct ffa_mem_region_attributes)) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out;
	}

	hyp_spin_lock(&host_kvm.ffa.lock);
	if (!host_kvm.ffa.tx) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	buf = ffa_buffers.tx;
	memcpy(buf, host_kvm.ffa.tx, fraglen);

	offset = buf->ep_mem_access[0].composite_off;
	if (!offset || buf->ep_count != 1) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	if (fraglen < offset + sizeof(struct ffa_composite_mem_region)) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	reg = (void *)buf + offset;
	nr_ranges = ((void *)buf + fraglen) - (void *)reg->constituents;
	if (nr_ranges % sizeof(reg->constituents[0])) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	nr_ranges /= sizeof(reg->constituents[0]);
	ret = ffa_host_share_ranges(reg->constituents, nr_ranges);
	if (ret)
		goto out_unlock;

	spmd_mem_share(res, len, fraglen);
	expected = (fraglen == len) ? FFA_SUCCESS : FFA_MEM_FRAG_RX;
	if (res->a0 != expected) {
		WARN_ON(ffa_host_unshare_ranges(reg->constituents,
						nr_ranges));
	}

out_unlock:
	hyp_spin_unlock(&host_kvm.ffa.lock);
out:
	if (ret)
		ffa_to_smccc_res(res, ret);
	return;
}

static void do_ffa_mem_reclaim(struct arm_smccc_res *res,
			       struct kvm_cpu_context *ctxt)
{
	DECLARE_REG(u32, handle_lo, ctxt, 1);
	DECLARE_REG(u32, handle_hi, ctxt, 2);
	DECLARE_REG(u32, flags, ctxt, 3);
	u32 offset, len, fraglen, fragoff, nr_ranges;
	struct ffa_composite_mem_region *reg;
	struct ffa_mem_region *buf;
	int ret = 0;
	u64 handle;

	handle = PACK_HANDLE(handle_lo, handle_hi);

	hyp_spin_lock(&host_kvm.ffa.lock);

	buf = ffa_buffers.tx;
	*buf = (struct ffa_mem_region) {
		.sender_id	= HOST_FFA_ID,
		.handle		= handle,
	};

	spmd_retrieve_req(res, sizeof(*buf));
	buf = ffa_buffers.rx;
	if (res->a0 != FFA_MEM_RETRIEVE_RESP)
		goto out_unlock;

	len = res->a1;
	fraglen = res->a2;

	offset = buf->ep_mem_access[0].composite_off;
	/*
	 * We can trust the SPMD to get this right, but let's at least
	 * check that we end up with something that doesn't look _completely_
	 * bogus.
	 */
	if (WARN_ON(offset > PAGE_SIZE)) {
		ret = FFA_RET_ABORTED;
		goto out_unlock;
	}

	reg = (void *)buf + offset;
	nr_ranges = ((void *)buf + fraglen) - (void *)reg->constituents;
	if (nr_ranges % sizeof(reg->constituents[0])) {
		ret = FFA_RET_INVALID_PARAMETERS;
		goto out_unlock;
	}

	nr_ranges /= sizeof(reg->constituents[0]);
	ret = ffa_host_unshare_ranges(reg->constituents, nr_ranges);
	if (ret)
		goto out_unlock;

	for (fragoff = fraglen; fragoff < len; fragoff += fraglen) {
		struct ffa_mem_region_addr_range *ranges = ffa_buffers.rx;

		spmd_mem_frag_rx(res, handle_lo, handle_hi, fragoff);
		fraglen = res->a3;
		nr_ranges = fraglen / sizeof(*ranges);

		/*
		 * There should be no reason for the SPMD to reply with anything
		 * else than FRAG_TX, and by now we've lost the previous
		 * fragments so we can't rollback the host stage-2 page-table
		 * changes. We can't just bail out otherwise nothing will
		 * prevent the host from sharing/donating these pages to guests,
		 * which is a security problem, so this must be fatal.
		 */
		BUG_ON(res->a0 != FFA_MEM_FRAG_TX);
		BUG_ON(ffa_host_unshare_ranges(ranges, nr_ranges));
	}

	spmd_mem_reclaim(res, handle_lo, handle_hi, flags);

	if (res->a0 != FFA_SUCCESS) {
		WARN_ON(ffa_host_share_ranges(reg->constituents,
					      reg->addr_range_cnt));
	}

out_unlock:
	hyp_spin_unlock(&host_kvm.ffa.lock);

	if (ret)
		ffa_to_smccc_res(res, ret);
	return;
}

/*
 * Filter out advertising unsupported features, and advertise features supported
 * by hyp with the properties that hyp supports.
 *
 * Return true if the feature query has been handled, or false if the query
 * should pass through.
 */
static bool do_ffa_features(struct arm_smccc_res *res,
			    struct kvm_cpu_context *ctxt)
{
	DECLARE_REG(u32, feat_func_id, ctxt, 1);

	switch (feat_func_id) {
	case FFA_RXTX_UNMAP:
	case FFA_ID_GET:
		ffa_to_smccc_res(res, FFA_RET_SUCCESS);
		return true;

	case FFA_MEM_LEND:
	case FFA_FN64_MEM_LEND:
	case FFA_MEM_SHARE:
	case FFA_FN64_MEM_SHARE:
		/*
		 * 0 for no support for transmission of a memory transaction
		 * descriptor in a buffer dynamically allocated by the endpoint.
		 */
		ffa_to_smccc_prop_res(res, FFA_RET_SUCCESS, 0);
		return true;

	case FFA_FN64_RXTX_MAP:
		/*
		 * Advertise the minimum buffer size and alignment boundary for
		 * the RX and TX buffers supported by hyp.
		 */
		ffa_to_smccc_prop_res(res, FFA_RET_SUCCESS, FFA_FEAT_BUFFER_ALIGN);
		return true;

	/* Not supported */
	case FFA_FN64_MEM_RETRIEVE_REQ:
	case FFA_MEM_RETRIEVE_RESP:
	case FFA_MEM_RELINQUISH:
	case FFA_MEM_OP_PAUSE:
	case FFA_MEM_OP_RESUME:
	case FFA_MEM_FRAG_RX:
	case FFA_FN64_MEM_DONATE:
	case FFA_MSG_SEND:
	case FFA_MSG_POLL:
	case FFA_MSG_WAIT:
	case FFA_MSG_SEND_DIRECT_REQ:
	case FFA_MSG_SEND_DIRECT_RESP:
	case FFA_RXTX_MAP:
	case FFA_MEM_DONATE:
	case FFA_MEM_RETRIEVE_REQ:
		ffa_to_smccc_res(res, FFA_RET_NOT_SUPPORTED);
		return true;

	/* Pass through */
	default:
		break;
	}

	return false;
}

static void do_ffa_id_get(struct arm_smccc_res *res,
			  struct kvm_cpu_context *ctxt)
{
	ffa_to_smccc_prop_res(res, FFA_RET_SUCCESS, HOST_FFA_ID);
}

bool kvm_host_ffa_handler(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(u32, func_id, host_ctxt, 0);
	struct arm_smccc_res res;

	if (!is_ffa_call(func_id))
		return false;

	switch (func_id) {
	/* Memory management */
	case FFA_FN64_RXTX_MAP:
		do_ffa_rxtx_map(&res, host_ctxt);
		goto out_handled;
	case FFA_RXTX_UNMAP:
		do_ffa_rxtx_unmap(&res, host_ctxt);
		goto out_handled;
	case FFA_MEM_SHARE:
	case FFA_FN64_MEM_SHARE:
		do_ffa_mem_share(&res, host_ctxt);
		goto out_handled;
	case FFA_MEM_RECLAIM:
		do_ffa_mem_reclaim(&res, host_ctxt);
		goto out_handled;
	case FFA_MEM_FRAG_TX:
		do_ffa_mem_frag_tx(&res, host_ctxt);
		goto out_handled;
	case FFA_FEATURES:
		if (!do_ffa_features(&res, host_ctxt))
			return false; /* Pass through */
		goto out_handled;
	case FFA_ID_GET:
		do_ffa_id_get(&res, host_ctxt);
		goto out_handled;
	case FFA_MEM_LEND:
	case FFA_FN64_MEM_LEND:
		break;
	/* Unsupported memory management calls */
	case FFA_FN64_MEM_RETRIEVE_REQ:
	case FFA_MEM_RETRIEVE_RESP:
	case FFA_MEM_RELINQUISH:
	case FFA_MEM_OP_PAUSE:
	case FFA_MEM_OP_RESUME:
	case FFA_MEM_FRAG_RX:
	case FFA_FN64_MEM_DONATE:
	/* Indirect message passing via RX/TX buffers */
	case FFA_MSG_SEND:
	case FFA_MSG_POLL:
	case FFA_MSG_WAIT:
	/* 32-bit variants of 64-bit calls */
	case FFA_MSG_SEND_DIRECT_REQ:
	case FFA_MSG_SEND_DIRECT_RESP:
	case FFA_RXTX_MAP:
	case FFA_MEM_DONATE:
	case FFA_MEM_RETRIEVE_REQ:
		break;
	default:
		return false; /* Pass through */
	}

	ffa_to_smccc_error(&res, FFA_RET_NOT_SUPPORTED);
out_handled:
	ffa_set_retval(host_ctxt, &res);
	return true;
}

int hyp_ffa_init(void *rx, void *tx)
{
	struct arm_smccc_res res;

	if (kvm_host_psci_config.smccc_version < ARM_SMCCC_VERSION_1_2)
		return 0;

	arm_smccc_1_1_smc(FFA_VERSION, FFA_VERSION_1_0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == FFA_RET_NOT_SUPPORTED)
		return 0;

	if (res.a0 != FFA_VERSION_1_0)
		return -EOPNOTSUPP;

	arm_smccc_1_1_smc(FFA_ID_GET, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 != FFA_SUCCESS)
		return -EOPNOTSUPP;

	if (res.a2 != HOST_FFA_ID)
		return -EINVAL;

	ffa_buffers = (struct kvm_ffa_buffers) {
		.lock	= __HYP_SPIN_LOCK_UNLOCKED,
		.tx	= tx,
		.rx	= rx,
	};

	host_kvm.ffa = (struct kvm_ffa_buffers) {
		.lock	= __HYP_SPIN_LOCK_UNLOCKED,
	};

	return 0;
}
