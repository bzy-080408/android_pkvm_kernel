
/*
FILES="$(find arch/arm64 -name "*.[ch]") include/kvm/arm_hypercalls.h";  spatch --sp-file vcpu_declr.cocci $FILES --in-place
*/

// <smpl>

@@
identifier vcpu;
expression E;
@@
<...
- struct kvm_vcpu *vcpu;
+ struct kvm_vcpu *vcpu = E;

- vcpu = E;
...>


/*
@@
identifier vcpu;
identifier f1, f2;
@@
f1(...)
{
- struct kvm_vcpu *vcpu = NULL;
+ struct kvm_vcpu *vcpu;
... when != f2(..., vcpu, ...)
}
*/

/*
@find_after@
identifier vcpu;
position p;
identifier f;
@@
<...
 struct kvm_vcpu *vcpu@p;
 ... when != vcpu = ...;
 f(..., vcpu, ...);
...>

@@
identifier vcpu;
expression E;
position p != find_after.p;
@@
<...
- struct kvm_vcpu *vcpu@p;
+ struct kvm_vcpu *vcpu = E;
 ...
- vcpu = E;
...>

*/

// </smpl>
