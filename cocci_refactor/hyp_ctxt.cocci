// Remove vcpu if all we're using is hypstate and ctxt

/*
FILES="$(find arch/arm64/kvm/hyp -name "*.[ch]")"
spatch --sp-file hyp_ctxt.cocci $FILES --in-place;
*/

// <smpl>

@remove@
identifier func !~ "^trap_|^access_|dbg_to_reg|check_pmu_access_disabled|match_mpidr|get_ctr_el0|emulate_cp|unhandled_cp_access|index_to_sys_reg_desc|kvm_pmu_|pmu_counter_idx_valid|reset_|read_from_write_only|write_to_read_only|undef_access|vgic_|kvm_handle_|handle_sve|handle_smc|handle_no_fpsimd|id_visibility|reg_to_dbg|ptrauth_visibility|sve_visibility|kvm_arch_sched_in|kvm_arch_vcpu_|kvm_vcpu_pmu_|kvm_psci_|kvm_arm_copy_fw_reg_indices|kvm_arm_pvtime_|kvm_trng_|kvm_arm_timer_";
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