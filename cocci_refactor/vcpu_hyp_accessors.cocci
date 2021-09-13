// <smpl>

/*
spatch --sp-file vcpu_hyp_accessors.cocci --dir arch/arm64 --include-headers --in-place
*/

@find_defines@
identifier macro;
identifier vcpu;
position p;
@@
#define macro(vcpu) vcpu@p

@@
identifier vcpu;
position p != find_defines.p;
@@
(
- vcpu@p->arch.hcr_el2
+ vcpu_hcr_el2(vcpu)
|
- vcpu@p->arch.mdcr_el2
+ vcpu_mdcr_el2(vcpu)
|
- vcpu@p->arch.vsesr_el2
+ vcpu_vsesr_el2(vcpu)
|
- vcpu@p->arch.fault
+ vcpu_fault(vcpu)
|
- vcpu@p->arch.flags
+ vcpu_flags(vcpu)
)

// </smpl>
