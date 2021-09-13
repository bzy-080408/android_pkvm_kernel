/*
 FILES="$(find arch/arm64 -name "*.[ch]") include/kvm/arm_hypercalls.h"; spatch --sp-file test.cocci $FILES

*/

@r@
identifier fn;
@@
fn(...) {
 hello;
 ...
}

@@
identifier r.fn;
@@
static fn(...) {
+ world;
 ...
}
