// <smpl>

/*
FILES="$(find arch/arm64/kvm/hyp -name "*.[ch]" ! -name "debug-sr*") arch/arm64/include/asm/kvm_hyp.h"
spatch --sp-file add_hypstate.cocci $FILES --in-place
*/

@exists@
identifier vcpu;
fresh identifier hyps = vcpu ## "_hyps";
identifier fc;
@@
<...
(
  struct kvm_vcpu *vcpu = NULL;
+ struct vcpu_hyp_state *hyps;
|
  struct kvm_vcpu *vcpu = ...;
+ struct vcpu_hyp_state *hyps = &hyp_state(vcpu);
|
  struct kvm_vcpu *vcpu;
+ struct vcpu_hyp_state *hyps;
)
<...
  vcpu = ...;
+ hyps = &hyp_state(vcpu);
...>
fc(..., vcpu, ...)
...>

@exists@
identifier func != {kvm_arch_vcpu_run_pid_change};
identifier vcpu;
fresh identifier hyps = vcpu ## "_hyps";
identifier fc;
@@
func(..., struct kvm_vcpu *vcpu, ...) {
+ struct vcpu_hyp_state *hyps = &hyp_state(vcpu);
<+...
fc(..., vcpu, ...)
...+>
 }

@@
expression a, b;
identifier vcpu;
fresh identifier hyps = vcpu ## "_hyps";
iterator name kvm_for_each_vcpu;
identifier fc;
@@
kvm_for_each_vcpu(a, vcpu, b)
 {
+ hyps = &hyp_state(vcpu);
<+...
fc(..., vcpu, ...)
...+>
 }

@@
identifier hyps, vcpu;
iterator name kvm_for_each_vcpu;
statement S1, S2;
@@
kvm_for_each_vcpu(...)
 {
- hyps = &hyp_state(vcpu);
... when != S1
+ hyps = &hyp_state(vcpu);
 S2
 ... when any
 }

@
disable optional_qualifier
exists
@
identifier vcpu, hyps;
@@
<...
  const struct kvm_vcpu *vcpu = ...;
- struct vcpu_hyp_state *hyps = &hyp_state(vcpu);
+ const struct vcpu_hyp_state *hyps = &hyp_state(vcpu);
...>


@@
identifier func, vcpu, hyps;
@@
func(..., const struct kvm_vcpu *vcpu, ...) {
- struct vcpu_hyp_state *hyps = &hyp_state(vcpu);
+ const struct vcpu_hyp_state *hyps = &hyp_state(vcpu);
...
 }

@exists@
identifier vcpu;
fresh identifier hyps = vcpu ## "_hyps";
@@
(
- vcpu_hcr_el2(vcpu)
+ hyp_state_hcr_el2(hyps)
|
- vcpu_mdcr_el2(vcpu)
+ hyp_state_mdcr_el2(hyps)
|
- vcpu_vsesr_el2(vcpu)
+ hyp_state_vsesr_el2(hyps)
|
- vcpu_fault(vcpu)
+ hyp_state_fault(hyps)
|
- vcpu_flags(vcpu)
+ hyp_state_flags(hyps)
|
- vcpu_has_sve(vcpu)
+ hyp_state_has_sve(hyps)
|
- vcpu_has_ptrauth(vcpu)
+ hyp_state_has_ptrauth(hyps)
|
- kvm_arm_vcpu_sve_finalized(vcpu)
+ kvm_arm_hyp_state_sve_finalized(hyps)
)

// </smpl>
