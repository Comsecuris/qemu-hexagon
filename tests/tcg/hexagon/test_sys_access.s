# Purpose: sys_access syscall test, the current file should be readable but not executable

    .text
    .globl _start
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
        r1=#4
        memw(r29+#0)=r0
    }
    {
        memw(r29+#4)=r1
    }
	{
        r0=#261
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
	.string	"./test_sys_access.tst"
	.size	.L.str, 19
