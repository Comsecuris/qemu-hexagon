# Purpose: demonstrate handling of .new uses appearing before the associated definition. Here we perform a jump that skips the code resetting R2 from 0xDEADBEEF to 0, only if P0.new is true, but P0 is assigned to 1 (R4) in the next instruction in the packet. A successful run of the program will show R2 retaining the 0xDEADBEEF value in the CPU dump.

    .text
    .globl _start

_start:
    {
        call init
    }
    { r2=#0xdeadbeef }
    { r4=#1 }
    {
		if (p0.new) jump:nt skip
	    p0=r4;
	}

fallthrough:
	{ r2=#0 }

skip:
    {
        p0 = cmp.eq(r2, #0xdeadbeef); if (p0.new) jump:t pass
        jump fail
    }
