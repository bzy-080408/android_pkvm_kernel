// <smpl>

// spatch --sp-file vcpu_hyp_state.cocci --no-includes --include-headers  --dir arch/arm64 --very-quiet --in-place

@@
expression vcpu;
@@
- vcpu->arch.
+ vcpu->arch.hyp_state.
(
 hcr_el2
|
 mdcr_el2
|
 vsesr_el2
|
 fault
|
 flags
|
 sysregs_loaded_on_cpu
)

@@
identifier arch;
@@
- arch.fault
+ arch.hyp_state.fault

// </smpl>