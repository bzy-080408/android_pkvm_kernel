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

static void ffa_to_smccc_res(struct arm_smccc_res *res, int ret)
{
	if (ret == FFA_RET_SUCCESS)
		*res = (struct arm_smccc_res) { .a0 = FFA_SUCCESS };
	else
		ffa_to_smccc_error(res, ret);
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

bool kvm_host_ffa_handler(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, func_id, host_ctxt, 0);
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
	case FFA_MEM_LEND:
	case FFA_FN64_MEM_LEND:
	case FFA_MEM_RECLAIM:
	case FFA_MEM_FRAG_TX:
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
