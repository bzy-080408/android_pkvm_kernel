# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2021 - Google LLC

CFLAGS += -std=gnu99 -I. -lpthread
SRCS := $(wildcard *.c)
PROGS := $(patsubst %.c,%,$(SRCS))

# Generated binaries to be installed by top KSFT script
TEST_GEN_PROGS := $(PROGS)

# Get Kernel headers installed and use them.
KSFT_KHDR_INSTALL := 1

# Include KSFT lib.mk.
include ../../lib.mk
