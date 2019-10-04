# Purpose: test a simple multiplication operation

    .text
    .globl _start

_start:
	{
		r5:4=#18446744073709551615
		r7:6=#255
	}
    {
        p0=vcmpb.eq(R5:4,R7:6)
    }
    {
        p0 = cmp.eq(r3, #24); if (p0.new) jump:t pass
        jump fail
    }
