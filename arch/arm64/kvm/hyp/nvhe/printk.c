// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 */

#include <linux/kernel.h>
#include <linux/kern_levels.h>
#include <linux/printk.h>
#include <linux/stdarg.h>
#include <../debug-pl011.h>

#define LOG_LINE_MAX 1024

int _printk(const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vprintk(fmt, args);
	va_end(args);

	return r;
}

int vprintk(const char *fmt, va_list args)
{
	return vprintk_emit(0, LOGLEVEL_DEFAULT, NULL, fmt, args);
}

/**
 * printk_parse_prefix - Parse level.
 *
 * @text:     The terminated text message.
 * @level:    A pointer to the current level value, will be updated.
 *
 * @level may be NULL if the caller is not interested in the parsed value.
 * Otherwise the variable pointed to by @level must be set to
 * LOGLEVEL_DEFAULT in order to be updated with the parsed value.
 *
 * Return: The length of the parsed level.
 */
static u16 printk_parse_prefix(const char *text, int *level)
{
	u16 prefix_len = 0;
	int kern_level;

	while (*text) {
		kern_level = printk_get_level(text);
		if (!kern_level)
			break;

		switch (kern_level) {
		case '0' ... '7':
			if (level && *level == LOGLEVEL_DEFAULT)
				*level = kern_level - '0';
			break;
		}

		prefix_len += 2;
		text += 2;
	}

	return prefix_len;
}

static u16 printk_sprint(char *text, u16 size, int facility, const char *fmt,
			 va_list args)
{
	u16 text_len;

	text_len = vscnprintf(text, size, fmt, args);

	/* Strip a trailing newline. */
	if (text_len && text[text_len - 1] == '\n')
		text_len--;

	return text_len;
}

int vprintk_emit(int facility, int level,
		 const struct dev_printk_info *dev_info, const char *fmt,
		 va_list args)
{
#ifdef CONFIG_KVM_ARM_HYP_DEBUG_UART
	char buffer[LOG_LINE_MAX];
	int printed_len;
	u16 prefix_len = 0;

	printed_len =
		printk_sprint(&buffer[0], LOG_LINE_MAX, facility, fmt, args);

	/* Extract log level. */
	if (facility == 0)
		prefix_len = printk_parse_prefix(&buffer[0], &level);

	/* Print to UART. */
	hyp_puts(&buffer[prefix_len]);

	return printed_len - prefix_len;
#else
	return 0;
#endif
}
