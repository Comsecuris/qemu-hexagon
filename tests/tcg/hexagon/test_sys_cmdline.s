# Purpose: sys_get_cmdline test, on success the command string is returned

    .text
    .globl _start

_start:
    {
        call init
    }
# sys_get_cmdline syscall
    {
        allocframe(r29,#16):raw
    }
    {
        r0=##.L.buf
    }
    {
        r1=#33
        memw(r29+#0)=r0
    }
    {
        memw(r29+#4)=r1
    }
	{
        r0=#21
        r1=r29
	}
	{
        trap0(#0)
	}
    {
        p0 = cmp.eq(r0, #0); if (p0.new) jump:t print
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
	.string	"./test_sys_read.s"
	.size	.L.str, 18

.L.buf:
    .skip 33
