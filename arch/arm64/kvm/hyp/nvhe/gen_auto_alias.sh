#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Author: David Brazdil <dbrazdil@google.com>
#

LC_ALL=C

HYP_NAMESPACE="__kvm_nvhe_"

# Note: https://bugs.llvm.org/show_bug.cgi?id=41886
# Must list .rela sections for llvm-objdump

# Allow all alternative callbacks
AUTO_SECTIONS=".rela.altinstructions "

# Allow all static keys
AUTO_SECTIONS+=".rela__jump_table "

fail() {
	echo "ERROR: $1" 1>&2
	exit 1
}

assert_defined() {
	test -v "$1" || fail "Environment variable $1 not defined"
}

starts_with() {
	case "$1" in
	"$2"*)	true;;
	*)	false;;
	esac
}

substr_from() {
	echo "$1" | cut -c${2}-
}

strlen() {
	echo -n "$1" | wc -m
}

assert_is_hyp_symbol() {
	if ! starts_with "$SYM" "$HYP_NAMESPACE"
	then
		fail "Unexpected symbol name: $SYM"
	fi
}

base_sym_name() {
	substr_from "$SYM" `strlen "$HYP_NAMESPACE"`
}

for_each_undef_symbol() {
	assert_defined "NM"

	"$NM" -u "$1" | while read LINE
	do
		if ! starts_with "$LINE" "U "
		then
			fail "Unexpected input: $LINE"
		fi

		substr_from "$LINE" 3
	done
}

list_relocs() {
	assert_defined "OBJDUMP"

	SECTION_ARGS=""
	for SECTION in $AUTO_SECTIONS
	do
		SECTION_ARGS+="-j$SECTION "
	done

	"$OBJDUMP" -r $SECTION_ARGS "$1"
}

list_contains_sym() {
	grep "$1" 1>/dev/null <<<"$2"
}

AUTO_LIST=`list_relocs "$1"`

for_each_undef_symbol "$1" | while read SYM
do
	if list_contains_sym "$SYM" "$AUTO_LIST"
	then
		echo "${HYP_NAMESPACE}${SYM} ${SYM}"
	fi
done
