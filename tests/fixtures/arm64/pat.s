# Real aarch64 functions, each exercising ONE P15 pattern idiom, plus a
# global data symbol for the string-ref-pair target.
#
# Built with binutils-aarch64 (aarch64-linux-gnu-as / -ld, no root):
#   aarch64-linux-gnu-as -o pat.o pat.s
#   aarch64-linux-gnu-ld -shared -o libpat.so pat.o
# (LD_LIBRARY_PATH needs the binutils lib dir for the cross `as`/`ld`.)
#
# Committed as a test fixture (tests/fixtures/arm64/pat.s) so the P19
# real-ARM64 e2e is reproducible. The mnemonics are the public ARMv8-A ISA
# (stable facts), chosen so native.py's classifier is verified on REAL r2
# 6.2.2 disasm — closing the P15 ARM64 positive-e2e gap (FakeRunner-only).

    .text

# P1 popcount-loop: clz, ror, eor consecutive
    .global popcnt
    .type   popcnt, %function
popcnt:
    clz   w1, w0
    ror   w2, w0, #1
    eor   w0, w1, w2
    ret
    .size popcnt, .-popcnt

# P2 case-fold-scan: orr Xd,Xd,#32 (r2 6 renders the imm as 0x20)
    .global casefold
    .type   casefold, %function
casefold:
    orr   w0, w0, #32
    ret
    .size casefold, .-casefold

# P3 bitset-test: tst Xd, Xn, lsl #imm (r2 6 renders 'lsl 3', no #)
    .global bitset
    .type   bitset, %function
bitset:
    tst   w0, w1, lsl #3
    ret
    .size bitset, .-bitset

# P4 tbz-bit0-parity: tbz Xd, #0 (r2 6 renders 'tbz w0, 0, ...')
    .global parity
    .type   parity, %function
parity:
    tbz   w0, #0, .Lparity_ret
.Lparity_ret:
    ret
    .size parity, .-parity

# P5 fused-madd: madd Xd, Xn, Xm, Xa
    .global affine
    .type   affine, %function
affine:
    madd  x0, x1, x2, x3
    ret
    .size affine, .-affine

# P6 string-ref-pair: adrp Xd,sym + add Xd,Xd,<sym> (r2 6 renders the pair
# without the pre-6 ':lo12:' label syntax — the classifier accepts both)
    .global stringref
    .type   stringref, %function
stringref:
    adrp  x0, p15msg
    add   x0, x0, :lo12:(p15msg)
    ldr   x0, [x0]
    ret
    .size stringref, .-stringref

    .section .rodata
    .balign 4
    .hidden p15msg
p15msg:
    .asciz "p15-stringref"
