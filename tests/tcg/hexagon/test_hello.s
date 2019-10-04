// Purpose: simple hello world program.

    .text
    .globl _start

_start:
    {
        call init
    }
	{ r0=#4; }
	{
		r1=##.L.str
	}
	{ trap0(#0); }
    {
        jump pass
    }

.L.str:
	.string	"Hello world!\n"
	.size	.L.str, 14
