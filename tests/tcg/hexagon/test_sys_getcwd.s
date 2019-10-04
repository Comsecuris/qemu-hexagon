# Purpose: sys_getcwd test, on success the current working directory is returned

    .text
    .globl _start

_start:
    {
        call init
    }
# sys_getcwd syscall
    {
        allocframe(r29,#16):raw
    }
    {
        r0=##.L.buf
    }
    {
        r1=#260
        memw(r29+#0)=r0
    }
    {
        memw(r29+#4)=r1
    }
	{
        r0=#260
        r1=r29
	}
	{
        trap0(#0)
	}
    {
        p0 = !cmp.eq(r0, #-1); if (p0.new) jump:t print
        jump fail
    }

print:
    {
        r0=#4
        r1=##.L.buf
    }
    {
        trap0(#0)
    }
    {
        jump pass
    }

.data

.L.str:
	.string	"./test_sys_getcwd.s"
	.size	.L.str, 18

.L.buf:
    .skip 33
