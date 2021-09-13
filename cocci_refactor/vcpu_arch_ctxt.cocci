// spatch --sp-file vcpu_arch_ctxt.cocci --no-includes --include-headers  --dir arch/arm64

// <smpl>
@@
identifier vcpu;
@@
(
- vcpu->arch.ctxt.regs
+ vcpu_gp_regs(vcpu)
|
- vcpu->arch.ctxt.fp_regs
+ vcpu_fp_regs(vcpu)
)
