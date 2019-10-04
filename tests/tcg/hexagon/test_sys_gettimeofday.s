# Purpose: sys_gettimeofday usage example, as a result of the syscall,
# the date and time struct is returned

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
        memw(r29+#0)=r0.new
    }
	{
        r0=#263
        r1=r29
	}
	{
        trap0(#0)
	}
    {
        p0 = !cmp.eq(r1, #0); if (p0.new) jump:t pass
        jump fail
    }

.data

.L.buf:
    .skip 16
