# Purpose: test example, verify the soundness of the vspliceb operation
# the operation is a binary splice of two 64bit operators
# 
#                 vspliceb(0xffffffffffffffff,0x0000000000000000,5) = 0x000000000000001f 

    .text
    .globl _start

_start:
    {
        call init
    }
	{
		r0=#4294967295
        r1=#4294967295
    }
    {
        r2=#0
        r3=#0
    }
	{
        r5:4=vspliceb(r1:0, r3:2, #5)
	}
    {
        p0 = cmp.eq(r4, #4294967295); if (p0.new) jump:t test2
        jump fail
    }

test2:
    {
        p0 = cmp.eq(r5, #255); if (p0.new) jump:t pass
        jump fail
    }
