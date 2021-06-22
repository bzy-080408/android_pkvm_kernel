// </smpl>

/*
spatch --sp-file use_ctxt_access.cocci --dir arch/arm64/kvm/ --include-headers --in-place
*/

@@
constant r;
@@
- __ctxt_sys_reg(&vcpu->arch.ctxt, r)
+ &__vcpu_sys_reg(vcpu, r)

@@
identifier r;
@@
- vcpu->arch.ctxt.regs.r
+ vcpu_gp_regs(vcpu)->r

@@
identifier r;
@@
- vcpu->arch.ctxt.fp_regs.r
+ vcpu_fp_regs(vcpu)->r

@@
identifier r;
fresh identifier accessor = "vcpu_" ## r;
@@
- &vcpu->arch.ctxt.r
+ accessor(vcpu)

@@
identifier r;
fresh identifier accessor = "vcpu_" ## r;
@@
- vcpu->arch.ctxt.r
+ *accessor(vcpu)

// </smpl>