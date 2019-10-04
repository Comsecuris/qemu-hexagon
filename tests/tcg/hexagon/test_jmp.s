# Purpose: test example, verify the soundness of the add operation

    .text
    .globl _start

_start:
    {
        call init
    }
	{
		r1=#0
		r2=#0
	}
	{
		r3=add(r2,r3)
	}
    {
        p0 = cmp.eq(r3, #0)
    }
    {
        if (p0) jump:t pass
    }
    {
        jump fail
    }
