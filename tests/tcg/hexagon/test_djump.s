# Purpose: show dual jumps actually work. This program features a packet where two jumps should (in theory) be performed if !P0. However, we correctly handle the situation by performing only the first one and ignoring the second one. This can be verified by checking that the CPU dump contains 0xDEADBEEF in R2.

    .text
    .globl _start

_start:
    {
        call init
    }
    {
        r1 = #255;
    }
    {
        p0 = r1;
    }
	{
        if (p0) jump:t pass
        jump fail
	}
