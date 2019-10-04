# Purpose: test that writes of a register in a packet are performed only after that packet has finished its execution.

    .text
    .globl _start

_start:
    {
        call init
    }
	{
		r2=#4
		r3=#6
	}
	{
		memw(sp+#0)=r2
	}
	{
		r3=memw(sp+#0)
		r0=add(r2,r3)
	}
    {
        p0 = cmp.eq(r0, #10); if (p0.new) jump:t pass
        jump fail
    }
