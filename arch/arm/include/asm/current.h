/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_ARM_CURRENT_H
#define _ASM_ARM_CURRENT_H

#ifndef __ASSEMBLY__

#ifdef CONFIG_CURRENT_POINTER_IN_TPIDRURO

static inline struct task_struct *get_current(void)
{
	struct task_struct *cur;

	asm("mrc p15, 0, %0, c13, c0, 3" : "=r"(cur));
	return cur;
}

#define current get_current()
#else
#include <asm-generic/current.h>
#endif /* CONFIG_CURRENT_POINTER_IN_TPIDRURO */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_ARM_CURRENT_H */
