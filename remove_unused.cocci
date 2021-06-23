// <smpl>

/*
spatch --sp-file remove_unused.cocci --dir arch/arm64/kvm/hyp --in-place --include-headers --force-diff
*/

@@
identifier hyps;
@@
{
...
(
- struct vcpu_hyp_state *hyps = ...;
|
- struct vcpu_hyp_state *hyps;
)
... when != hyps
    when != if (...) { <+...hyps...+> }
?- hyps = ...;
... when != hyps
    when != if (...) { <+...hyps...+> }
}

@@
identifier vcpu_ctxt;
@@
{
...
(
- struct kvm_cpu_context *vcpu_ctxt = ...;
|
- struct kvm_cpu_context *vcpu_ctxt;
)
... when != vcpu_ctxt
    when != if (...) { <+...vcpu_ctxt...+> }
?- vcpu_ctxt = ...;
... when != vcpu_ctxt
    when != if (...) { <+...vcpu_ctxt...+> }
}

@@
identifier x;
identifier func;
statement S;
@@
func(...)
 {
...
struct kvm_cpu_context *x = ...;
+
S
...
 }

@@
identifier x;
identifier func;
statement S;
@@
func(...)
 {
...
struct vcpu_hyp_state *x = ...;
+
S
...
 }

// </smpl>
