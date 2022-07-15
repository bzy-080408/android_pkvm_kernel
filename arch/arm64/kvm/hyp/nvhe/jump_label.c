// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 Google LLC
 * Author: Vincent Donnefort <vdonnefort@google.com>
 */

#include <nvhe/jump_label.h>
#include <nvhe/mm.h>
#include <nvhe/spinlock.h>

#include <linux/jump_label.h>
#include <linux/sizes.h>

static DEFINE_HYP_SPINLOCK(hyp_jump_label_lock);

static bool hyp_jump_label_is_sane(struct jump_entry *entry)
{
	unsigned long pc = jump_entry_code(entry);
	unsigned long target = jump_entry_target(entry);
	long offset;

	/* A64 insns must be word aligned */
	if ((pc & 0x3) || (target & 0x3))
		return false;

	/* B support ]-128M, 128M] offset */
	offset = (long)target - (long)pc;
	if (offset < -SZ_128M || offset >= SZ_128M)
		return false;

	return true;
}

static void hyp_insn_patch_text(void *addr, u32 insn)
{
	void *waddr = hyp_fixmap_map(hyp_virt_to_phys(addr));

	/* A64 insns are always LE */
	*((u32 *)waddr) = cpu_to_le32(insn);

	caches_clean_inval_pou((unsigned long)addr,
			       (unsigned long)addr + AARCH64_INSN_SIZE);
	hyp_fixmap_unmap();
}

static void hyp_jump_label_transform(struct jump_entry *entry,
				     enum jump_label_type type)
{
	void *addr = (void *)jump_entry_code(entry);
	unsigned long target = jump_entry_target(entry);
	u32 insn;

	if (!hyp_jump_label_is_sane(entry)) {
		WARN_ON_ONCE(1);
		return;
	}

	if (type == JUMP_LABEL_JMP) {
		u32 mask = BIT(26) - 1;
		u64 imm = ((long)target - (long)addr) >> 2;

		insn = aarch64_insn_get_b_value() & ~mask;
		insn |= imm & mask;
	} else {
		insn = aarch64_insn_get_hint_value() | AARCH64_INSN_HINT_NOP;
	}

	hyp_insn_patch_text(addr, insn);
}

static void hyp_jump_label_update(struct static_key *key)
{
	struct jump_entry *entry, *end = (struct jump_entry *)__hyp_jump_table_end;

	if (key->type & JUMP_TYPE_LINKED) {
		WARN_ON(1);
		return;
	}

	entry = (struct jump_entry *)(key->type & ~JUMP_TYPE_MASK);
	if (!entry)
		return;

	for (; entry < end && jump_entry_key(entry) == key; entry++)
		hyp_jump_label_transform(entry, jump_label_type(entry));
}

int create_hyp_jump_label_mappings(void)
{
	struct jump_entry *entry, *start, *end;
	struct static_key *prev_key, *key;
	int ret;

	start = (struct jump_entry *)__hyp_jump_table_start;
	end = (struct jump_entry *)__hyp_jump_table_end;

	ret = pkvm_create_mappings(start, end, PAGE_HYP_RO);
	if (ret)
		return ret;

	/*
	 * The host has init the table with its own VA. Convert them.
	 */
	for (entry = start; entry < end; entry++) {
		unsigned long type;

		key = jump_entry_key(entry);

		/* Unsupported */
		if (key->type & JUMP_TYPE_LINKED)
			continue;

		if (key == prev_key)
			continue;

		prev_key = key;

		type = key->type & JUMP_TYPE_MASK;
		key->entries = entry;
		key->type |= type;
	}

	return 0;
}

int static_key_count(struct static_key *key)
{
	return atomic_read(&key->enabled);
}

void static_key_enable(struct static_key *key)
{
	if (atomic_read(&key->enabled) > 0)
		return;

	hyp_spin_lock(&hyp_jump_label_lock);
	if (atomic_read(&key->enabled) == 0) {
		atomic_set(&key->enabled, 1);
		hyp_jump_label_update(key);
	}
	hyp_spin_unlock(&hyp_jump_label_lock);
}

void static_key_disable(struct static_key *key)
{
	if (atomic_read(&key->enabled) != 1) {
		WARN_ON_ONCE(atomic_read(&key->enabled) != 0);
		return;
	}

	hyp_spin_lock(&hyp_jump_label_lock);
	if (atomic_read(&key->enabled) == 1) {
		atomic_set(&key->enabled, 0);
		hyp_jump_label_update(key);
	}
	hyp_spin_unlock(&hyp_jump_label_lock);
}
