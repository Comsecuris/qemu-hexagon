# Purpose: sys_flen syscall test, on success, the file length is returned

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
        r1=#0
        memw(r29+#0)=r0
    }
    {
        r2=#16
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
# sys_flen syscall
    {
        memw(r29+#0)=r0
    }
	{
        r0=#12
        r1=r29
	}
	{
        trap0(#0)
	}
    {
        p0 = cmp.eq(r0, #19); if (p0.new) jump:t pass
        jump fail
    }

.L.str:
	.string	"test_file.txt"
	.size	.L.str, 13
