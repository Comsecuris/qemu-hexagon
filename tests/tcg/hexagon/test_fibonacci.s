# Purpose: computes the Fibonacci series up to a constant number.

    .text
    .globl _start

_start:
    {
        call init
    }
	{
		r2=#100
	}
	{
		p0=cmp.gt(r2,#0); if (!p0.new) jump:nt .LBB0_3
	}
	{
		r3=#0
		r4=#1
	}
.LBB0_2:                                // %while.body
	{
		r5=r4
	}
	{
		p0=cmp.gt(r2,r5); if (p0.new) jump:nt .LBB0_2
		r4=add(r3,r4)
		r3=r5
	}
.LBB0_3:                                // %while.end
    {
        p0 = cmp.eq(r3, #144); if (p0.new) jump:t pass
        jump fail
    }
