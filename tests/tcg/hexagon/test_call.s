// Purpose: test function calls and duplex instructions. The string "Hello there, I'm a test string!" with the first letter replaced with a capital L should be printed out.

    .text
	.globl	test
test:                                   // @test
	{
		jumpr r31
		memb(r0+#0)=#76
	}
.Lfunc_end0:
.Ltmp0:
	.size	test, .Ltmp0-test

	.globl	_start
_start:                                 // @_start
    {
        call init
    }
	{
		call test
		r0=##dummy_buffer
		allocframe(#0)
	}
	{
		call write
	}
    {
        jump pass
    }
	{
		r31:30=deallocframe(r30):raw
	}
.Lfunc_end1:
.Ltmp1:
	.size	_start, .Ltmp1-_start
write:                                  // @write
	{
		r2=##dummy_buffer
	}
	{ r0=r2; }
	{
		r2=#256
	}
	{ r1=r2; }
	{ trap0(#7); }
	{
		jumpr r31
	}
.Lfunc_end2:
.Ltmp2:
	.size	write, .Ltmp2-write

	.type	dummy_buffer,@object    // @dummy_buffer
	.data
	.globl	dummy_buffer
	.p2align	3
dummy_buffer:
	.string	"Hello there, I'm a test string!\n\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
	.size	dummy_buffer, 256
