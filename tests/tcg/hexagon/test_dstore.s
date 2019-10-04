# Purpose: test dual stores correctness. In this example the values 1 and 2 are both written on the top of the stack in a single packet. The value is then read back in R3, which should contain only the latest value written (2).

    .text
    .globl _start

_start:
    {
        call init
    }
	{
		r0=#1
		r1=#2
	}
	{
		memw(sp+#0)=r0
		memw(sp+#0)=r1
	}
	{
		r3=memw(sp+#0)
	}
    {
        p0 = cmp.eq(r3, #2); if (p0.new) jump:t pass
        jump fail
    }
