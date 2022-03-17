#!/bin/bash

CBMC=cbmc
TARGET_FILE=arch/arm64/kvm/hyp/nvhe/kvm_nvhe.gb

CHECKS="--bounds-check \
  --pointer-check \
  --div-by-zero-check \
  --signed-overflow-check \
  --unsigned-overflow-check \
  --pointer-overflow-check \
  --conversion-check \
  --undefined-shift-check \
  --float-overflow-check \
  --nan-check \
  --enum-range-check"

$CBMC \
  $CHECKS \
  --nondet-static \
  --trace \
  --trace-show-code \
  --trace-show-function-calls \
  $@ \
  $TARGET_FILE
