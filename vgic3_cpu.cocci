// <smpl>

/*
spatch --sp-file vgic3_cpu.cocci arch/arm64/kvm/hyp/vgic-v3-sr.c --in-place
*/


@@
identifier vcpu;
fresh identifier vcpu_hyps = vcpu ## "_hyps";
@@
(
- kvm_vcpu_sys_get_rt
+ kvm_hyp_state_sys_get_rt
|
- kvm_vcpu_get_esr
+ kvm_hyp_state_get_esr
)
- (vcpu)
+ (vcpu_hyps)

@add_cpu_if@
identifier func;
identifier c;
@@
int func(
- struct kvm_vcpu *vcpu
+ struct vgic_v3_cpu_if *cpu_if
 , ...)
{
<+...
- vcpu->arch.vgic_cpu.vgic_v3.c
+ cpu_if->c
...+>
}

@@
identifier func = add_cpu_if.func;
@@
 func(
- vcpu
+ cpu_if
 , ...
 )


@add_vgic_ctxt_hyps@
identifier func;
@@
void func(
- struct kvm_vcpu *vcpu
+ struct vgic_v3_cpu_if *cpu_if, struct kvm_cpu_context *vcpu_ctxt, struct vcpu_hyp_state *vcpu_hyps
 , ...) {
?- struct vcpu_hyp_state *vcpu_hyps = ...;
?- struct kvm_cpu_context *vcpu_ctxt = ...;
 ...
 }

@@
identifier func = add_vgic_ctxt_hyps.func;
@@
 func(
- vcpu,
+ cpu_if, vcpu_ctxt, vcpu_hyps,
 ...
 )


@find_calls@
identifier fn;
type a, b;
@@
- void (*fn)(struct kvm_vcpu *, a, b);
+ void (*fn)(struct vgic_v3_cpu_if *, struct kvm_cpu_context *, struct vcpu_hyp_state *, a, b);

@@
identifier fn = find_calls.fn;
identifier a, b;
@@
- fn(vcpu, a, b);
+ fn(cpu_if, vcpu_ctxt, vcpu_hyps, a, b);

@@
@@
int __vgic_v3_perform_cpuif_access(struct kvm_vcpu *vcpu) {
+ struct vgic_v3_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v3;
...
}

@remove@
identifier func;
identifier vcpu;
fresh identifier vcpu_ctxt = vcpu ## "_ctxt";
fresh identifier vcpu_hyps = vcpu ## "_hyps";
identifier hyps_remove;
identifier ctxt_remove;
@@
func(...,
- struct kvm_vcpu *vcpu
+ struct kvm_cpu_context *vcpu_ctxt, struct vcpu_hyp_state *vcpu_hyps
,...) {
?- struct vcpu_hyp_state *hyps_remove = ...;
?- struct kvm_cpu_context *ctxt_remove = ...;
... when != vcpu
 }

@@
identifier vcpu;
fresh identifier vcpu_ctxt = vcpu ## "_ctxt";
fresh identifier vcpu_hyps = vcpu ## "_hyps";
identifier remove.func;
@@
 func(
- vcpu
+ vcpu_ctxt, vcpu_hyps
  , ...)

// </smpl>
