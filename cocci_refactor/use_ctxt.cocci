// <smpl>
/*
spatch --sp-file use_ctxt.cocci  --dir arch/arm64/kvm/hyp --ignore debug-sr --include-headers  --in-place
spatch --sp-file use_ctxt.cocci  --dir arch/arm64/kvm/hyp --ignore debug-sr --include-headers  --in-place
*/

@remove_vcpu@
identifier vcpu;
fresh identifier vcpu_ctxt = vcpu ## "_ctxt";
identifier ctxt_remove;
identifier func !~ "(reset_unknown|reset_val|kvm_pmu_valid_counter_mask|reset_pmcr|kvm_arch_vcpu_in_kernel|__vgic_v3_)";
@@
func(
- struct kvm_vcpu *vcpu
+ struct kvm_cpu_context *vcpu_ctxt
, ...) {
- struct kvm_cpu_context *ctxt_remove = ...;
... when != vcpu
    when != if (...) { <+...vcpu...+> }
}

@@
identifier vcpu;
fresh identifier vcpu_ctxt = vcpu ## "_ctxt";
identifier func = remove_vcpu.func;
@@
func(
- vcpu
+ vcpu_ctxt
  , ...)

// </smpl>
