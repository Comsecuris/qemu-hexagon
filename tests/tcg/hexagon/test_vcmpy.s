# Purpose: test example, verify the soundness of the vcmpy operation
# this operation is a complex multiply and accumulate on vectors of two values
# 
#                       (3j+5 * 2j+4) + (4j+6 * 5j+2) = 22j+14
# the complex multiply between  0x00030005 and 0x00020004 is 0x000000160000000e
# the complex multiply between  0x00040006 and 0x00050002 is 0x000000160000000e

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
        r2=#262150
        r3=#327682
    }
	{
        r5:4=vcmpyr(r1:0, r3:2):sat
        r7:6=vcmpyi(r1:0, r3:2):sat
	}
    {
        p0 = cmp.eq(r4, #18); if (p0.new) jump:t test2
        jump fail
    }

test2:
    {
        p0 = cmp.eq(r5, #-2); if (p0.new) jump:t test3
        jump fail
    }

test3:
    {
        p0 = cmp.eq(r6, #38); if (p0.new) jump:t test4
        jump fail
    }

test4:
    {
        p0 = cmp.eq(r7, #24); if (p0.new) jump:t pass
        jump fail
    }
