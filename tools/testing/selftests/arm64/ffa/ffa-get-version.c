// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 */

#include "../../kselftest.h"

int main(int argc, char **argv)
{
	ksft_print_header();
        ksft_set_plan(1);

        // TODO: Install test kernel module
        // TODO: Use custom ioctl to call FFA_VERSION and get response
        // TODO: Use custom ioctl to call FFA_FN64_RXTX_MAP and get response

        ksft_test_result_fail("Some error");

	ksft_exit_pass();

        return 0;
}
