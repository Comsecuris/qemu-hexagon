# Purpose: test the soundness of the lsr operation

    .text
    .globl _start

_start:
    {
        call init
    }
	{
		r0=#0xffff2168
		r1=#0x7fffffff
	}
    {
        r2=#0x19
    }
	{
		r0&=lsr(r1, r2)
	}
    {
        p0 = cmp.eq(r0, #0x28); if (p0.new) jump:t test2
        jump fail
    }

test2:
	{
		r0=#0x0000000a
		r1=#0x00000000
	}
    {
        r2=#0xffffffff
    }
    {
        r1:0=lsl(r1:0, r2)
    }
    {
        p0 = cmp.eq(r0, #0x5); if (p0.new) jump:t pass
        jump fail
    }
