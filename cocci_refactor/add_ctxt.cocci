// <smpl>

/*
spatch --sp-file add_ctxt.cocci --dir arch/arm64/kvm/hyp --ignore arch/arm64/kvm/hyp/nvhe/debug-sr.c --ignore arch/arm64/kvm/hyp/vhe/debug-sr.c --include-headers --in-place
*/


@exists@
identifier vcpu;
fresh identifier vcpu_ctxt = vcpu ## "_ctxt";
identifier fc;
@@
<...
(
  struct kvm_vcpu *vcpu = NULL;
+ struct kvm_cpu_context *vcpu_ctxt;
|
  struct kvm_vcpu *vcpu = ...;
+ struct kvm_cpu_context *vcpu_ctxt = &vcpu_ctxt(vcpu);
|
  struct kvm_vcpu *vcpu;
+ struct kvm_cpu_context *vcpu_ctxt;
)
<...
  vcpu = ...;
+ vcpu_ctxt = &vcpu_ctxt(vcpu);
...>
fc(..., vcpu, ...)
...>

@exists@
identifier func != {kvm_arch_vcpu_run_pid_change};
identifier fc != {vcpu_ctxt};
identifier vcpu;
fresh identifier vcpu_ctxt = vcpu ## "_ctxt";
@@
func(..., struct kvm_vcpu *vcpu, ...) {
+ struct kvm_cpu_context *vcpu_ctxt = &vcpu_ctxt(vcpu);
<+...
fc(..., vcpu, ...)
...+>
 }

@@
expression a, b;
identifier vcpu;
fresh identifier vcpu_ctxt = vcpu ## "_ctxt";
iterator name kvm_for_each_vcpu;
identifier fc;
@@
kvm_for_each_vcpu(a, vcpu, b)
 {
+ vcpu_ctxt = &vcpu_ctxt(vcpu);
<+...
fc(..., vcpu, ...)
...+>
 }

@@
identifier vcpu_ctxt, vcpu;
iterator name kvm_for_each_vcpu;
type T;
identifier x;
statement S1, S2;
@@
kvm_for_each_vcpu(...)
 {
- vcpu_ctxt = &vcpu_ctxt(vcpu);
... when != S1
+ vcpu_ctxt = &vcpu_ctxt(vcpu);
 S2
 ... when any
 }

@
disable optional_qualifier
exists
@
identifier vcpu;
identifier vcpu_ctxt;
@@
<...
  const struct kvm_vcpu *vcpu = ...;
- struct kvm_cpu_context *vcpu_ctxt = &vcpu_ctxt(vcpu);
+ const struct kvm_cpu_context *vcpu_ctxt = &vcpu_ctxt(vcpu);
...>

@disable optional_qualifier@
identifier func, vcpu;
identifier vcpu_ctxt;
@@
func(..., const struct kvm_vcpu *vcpu, ...) {
- struct kvm_cpu_context *vcpu_ctxt = &vcpu_ctxt(vcpu);
+ const struct kvm_cpu_context *vcpu_ctxt = &vcpu_ctxt(vcpu);
...
 }

@exists@
expression r1, r2;
identifier vcpu;
fresh identifier vcpu_ctxt = vcpu ## "_ctxt";
@@
(
- vcpu_gp_regs(vcpu)
+ ctxt_gp_regs(vcpu_ctxt)
|
- vcpu_spsr_abt(vcpu)
+ ctxt_spsr_abt(vcpu_ctxt)
|
- vcpu_spsr_und(vcpu)
+ ctxt_spsr_und(vcpu_ctxt)
|
- vcpu_spsr_irq(vcpu)
+ ctxt_spsr_irq(vcpu_ctxt)
|
- vcpu_spsr_fiq(vcpu)
+ ctxt_spsr_fiq(vcpu_ctxt)
|
- vcpu_fp_regs(vcpu)
+ ctxt_fp_regs(vcpu_ctxt)
|
- __vcpu_sys_reg(vcpu, r1)
+ ctxt_sys_reg(vcpu_ctxt, r1)
|
- __vcpu_read_sys_reg(vcpu, r1)
+ __ctxt_read_sys_reg(vcpu_ctxt, r1)
|
- __vcpu_write_sys_reg(vcpu, r1, r2)
+ __ctxt_write_sys_reg(vcpu_ctxt, r1, r2)
|
- __vcpu_write_spsr(vcpu, r1)
+ __ctxt_write_spsr(vcpu_ctxt, r1)
|
- __vcpu_write_spsr_abt(vcpu, r1)
+ __ctxt_write_spsr_abt(vcpu_ctxt, r1)
|
- __vcpu_write_spsr_und(vcpu, r1)
+ __ctxt_write_spsr_und(vcpu_ctxt, r1)
|
- vcpu_pc(vcpu)
+ ctxt_pc(vcpu_ctxt)
|
- vcpu_cpsr(vcpu)
+ ctxt_cpsr(vcpu_ctxt)
|
- vcpu_mode_is_32bit(vcpu)
+ ctxt_mode_is_32bit(vcpu_ctxt)
|
- vcpu_set_thumb(vcpu)
+ ctxt_set_thumb(vcpu_ctxt)
|
- vcpu_get_reg(vcpu, r1)
+ ctxt_get_reg(vcpu_ctxt, r1)
|
- vcpu_set_reg(vcpu, r1, r2)
+ ctxt_set_reg(vcpu_ctxt, r1, r2)
)


/* Handles one case of a call within a call. */
@@
expression r1, r2;
identifier vcpu;
fresh identifier vcpu_ctxt = vcpu ## "_ctxt";
@@
- vcpu_pc(vcpu)
+ ctxt_pc(vcpu_ctxt)

// </smpl>
