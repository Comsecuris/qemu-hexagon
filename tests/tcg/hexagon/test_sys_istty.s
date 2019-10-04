# Purpose: sys_isatty syscall test, distinguish a tty from a file

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

test1:
# negative sys_isatty syscall
    {
        memw(r29+#0)=r0
    }
    {
        r0=#9
        r1=r29
    }
    {
        trap0(#0)
    }
    {
        p0 = cmp.eq(r0, #0); if (p0.new) jump:t test2
        jump fail
    }

test2:
# positive sys_isatty syscall
    {
        r0=##.L.tty
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
    {
        memw(r29+#0)=r0
    }
    {
        r0=#9
        r1=r29
    }
    {
        trap0(#0)
    }
    {
        p0 = cmp.eq(r0, #1); if (p0.new) jump:t pass
        jump fail
    }

.data

.L.str:
	.string	"./test_sys_istty.s"
	.size	.L.str, 18

.L.tty:
	.string	":tt"
	.size	.L.str, 4

.L.buf:
    .skip 33
