// spatch --sp-file el2_def_flags.cocci --no-includes --include-headers  --dir arch/arm64

// <smpl>
@@
expression vcpu;
@@

- vcpu->arch.flags
+ vcpu_flags(vcpu)
// </smpl>