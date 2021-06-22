// <smpl>

/*
FILES="$(find arch/arm64/kvm/hyp -name "*.[ch]" ! -name "debug-sr*") arch/arm64/include/asm/kvm_hyp.h"
spatch --sp-file use_hypstate.cocci $FILES --in-place
*/


@remove_vcpu_hyps@
identifier vcpu;
fresh identifier hyps = vcpu ## "_hyps";
identifier hyps_remove;
identifier func;
@@
func(
- struct kvm_vcpu *vcpu
+ struct vcpu_hyp_state *hyps
, ...) {
- struct vcpu_hyp_state *hyps_remove = ...;
... when != vcpu
    when != if (...) { <+...vcpu...+> }
}

@@
identifier vcpu;
fresh identifier hyps = vcpu ## "_hyps";
identifier func = remove_vcpu_hyps.func;
@@
func(
- vcpu
+ hyps
  , ...)

@remove_vcpu_hyps_ctxt@
identifier vcpu;
fresh identifier hyps = vcpu ## "_hyps";
identifier hyps_remove;
identifier ctxt_remove;
identifier func;
@@
func(
- struct kvm_vcpu *vcpu
+ struct vcpu_hyp_state *hyps
, ...) {
- struct vcpu_hyp_state *hyps_remove = ...;
- struct kvm_cpu_context *ctxt_remove = ...;
... when != vcpu
    when != if (...) { <+...vcpu...+> }
    when != ctxt_remove
    when != if (...) { <+...ctxt_remove...+> }
}

@@
identifier vcpu;
fresh identifier hyps = vcpu ## "_hyps";
identifier func = remove_vcpu_hyps_ctxt.func;
@@
func(
- vcpu
+ hyps
  , ...)

// </smpl>
