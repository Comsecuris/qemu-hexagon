# Purpose: test example, verify the soundness of the vector compare bytes operation
# 
# Vector word comparison between 0x1234567887654321 and 0x1234567800000000 should result in 0x11110000

    .text
    .globl _start

_start:
    {
        call init
    }
	{
		r0=#305419896
        r1=#2271560481
    }
    {
        r2=#305419896
        r3=#0
    }
	{
        p2=vcmpb.eq(r1:0, r3:2)
	}
    {
        r4=p2
    }
    {
        p0 = cmp.eq(r4, #15); if (p0.new) jump:t pass
        jump fail
    }
