# Purpose: test example, verify the soundness of the cmpy operation
# 
#                       3j+5 * 2j+4 = 22j+14
# the complex multiply between  0x00030005 and 0x00020004 is 0x000000160000000e

    .text
    .globl _start

_start:
    {
        call init
    }
	{
		r0=#196613
        r1=#131076
    }
	{
        r3:2=cmpy(r0, r1):sat
	}
    {
        p0 = cmp.eq(r2, #14); if (p0.new) jump:t test2
        jump fail
    }

test2:
    {
        p0 = cmp.eq(r3, #22); if (p0.new) jump:t pass
        jump fail
    }
