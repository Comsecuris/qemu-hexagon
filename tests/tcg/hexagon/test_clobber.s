# Purpose: demonstrate the succesful operation of the register save mechanism, in which the caller saves the registers that will be clobbered, and restores them after the call.

    .text
    .globl _start

_start:
    {
        call init
    }
    {
        r16=#47
        r17=#155
    }
    {
        memd(r29+#-16)=r17:16; allocframe(#8)
    }
    {
        r16=#255
        r17=#42
    }
    {
        r17:16=memd(r29+#0); deallocframe
    }
	{
		r3=add(r16,r17)
	}
    {
        p0 = cmp.eq(r3, #202); if (p0.new) jump:t pass
    }
    {
        jump fail
    }
