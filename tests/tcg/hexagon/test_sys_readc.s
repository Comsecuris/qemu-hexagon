# Purpose: sys_readc syscall test, on success, a single character is read

    .text
    .globl _start

_start:
    {
        call init
    }
# sys_readc syscall
    {
        r0=#7
        r1=#0
    }
    {
        trap0(#0)
    }
# compare the first read character, should be a hash symbol
    {
        p0 = cmp.eq(r0, #35); if (p0.new) jump:t pass
        jump fail
    }
