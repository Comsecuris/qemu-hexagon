# Purpose: sys_open syscall test, on success, r0 contains a file handle

    .text
    .globl _start
    .set len, 18

_start:
    {
        call init
    }
    {
        allocframe(r29,#24):raw
    }
    {
        r0=##.L.str
    }
    {
        r1=#0
        memw(r29+#0)=r0; memw(r29+#4)=r1
    }
    {
        r0=#len
        memw(r29+#8)=r0
    }
	{
        r0=#1  
        r1=r29
	}
	{
        trap0(#0)
	}
    {
        p0 = !cmp.eq(r0, #-1); if (p0.new) jump:t pass
        jump fail
    }

.L.str:
	.string	"test_sys_open.tst"
	.size	.L.str, len
