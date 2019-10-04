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
        memw(r29+#0)=r0.new
    }
	{
        r0=#22
        r1=r29
	}
	{
        trap0(#0)
	}
    {
        p0 = !cmp.eq(r0, #-1); if (p0.new) jump:t pass
        jump fail
    }

.data

.L.buf:
    .skip 16
