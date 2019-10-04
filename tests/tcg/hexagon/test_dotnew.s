// Purpose: test the .new operator while performing memory stores. In the final CPU dump R0 should contain 3, R1 should contain 2 and R2 should contain 1.

    .text
    .globl _start

_start:
    {
        call init
    }
	{
		r0=#1
		memw(sp+#0)=r0.new
	}
	{
		r1=#2
		memw(sp+#4)=r1.new
	}
	{
		r2=#3
		memw(sp+#8)=r2.new
	}
	{
		r0=memw(sp+#8)
	}
	{
		r1=memw(sp+#4)
	}
	{
		r2=memw(sp+#0)
	}
	{
		r3=mpyi(r1,r2)
	}
    {
        p0 = cmp.eq(r3, #2); if (p0.new) jump:t pass
        jump fail
    }
