# Purpose: sys_clock usage example, as a result of the syscall, the register r0 should
# contain the number of centiseconds since the execution started.

    .text
    .globl _start

_start:
    {
        call init
    }
	{
        r0=#16;
	}
	{
        trap0(#0);
	}
    {
        p0 = !cmp.eq(r0, #-1); if (p0.new) jump:t pass
        jump fail
    }
