# Purpose: test a multiple predicate AND combination

    .text
    .globl _start

_start:
    {
        call init
    }
    {
        r0=#0
        r1=#1
    }
	{
        p0=cmp.gt(r0,r1)
        p0=cmp.gt(r0,r1)
        p0=cmp.gt(r1,r0)
    }
    {
        if (!p0) jump:t pass
        jump fail
    }
