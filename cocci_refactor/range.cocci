

// <smpl>

/*
 FILES="$(find arch/arm64 -name "*.[ch]") include/kvm/arm_hypercalls.h"; spatch --sp-file range.cocci $FILES
*/

@initialize:python@
@@
starts = ("start", "begin", "from", "floor", "addr", "kaddr")
ends = ("size", "length", "len")

//ends = ("end", "to", "ceiling", "size", "length", "len")


@start_end@
identifier f;
type A, B;
identifier start, end;
parameter list[n] ps;
@@
f(ps, A start, B end, ...) {
...
}

@script:python@
start << start_end.start;
end << start_end.end;
ta << start_end.A;
tb << start_end.B;
@@

if ta != tb and tb != "size_t":
        cocci.include_match(False)
elif not any(x in start for x in starts) and not any(x in end for x in ends):
        cocci.include_match(False)

@@
identifier f = start_end.f;
expression list[start_end.n] xs;
expression a, b;
@@
(
* f(xs, a, a, ...)
|
* f(xs, a, a - b, ...)
)

// </smpl>