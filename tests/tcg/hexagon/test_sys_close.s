# Purpose: sys_close syscall test, on success, 0 is returned

    .text
    .globl _start
    .set len, 20

_start:
    {
        call init
    }
# sys_open syscall
    {
        allocframe(r29,#16):raw
    }
    {
        r0=##.L.str
    }
    {
        r1=#0
        memw(r29+#0)=r0
    }
    {
        r2=#len
        memw(r29+#4)=r1
    }
    {
        memw(r29+#8)=r2
    }
	{
        r0=#1  
        r1=r29
	}
	{
        trap0(#0)
	}
# sys_close syscall
    {
        memw(r29+#0)=r0
    }
    {
        r0=#2
        r1=r29
    }
    {
        trap0(#0)
    }
    {
        p0 = cmp.eq(r0, #0); if (p0.new) jump:t pass
        jump fail
    }

.data

.L.str:
	.string	"./test_sys_close.tst"
	.size	.L.str, len
