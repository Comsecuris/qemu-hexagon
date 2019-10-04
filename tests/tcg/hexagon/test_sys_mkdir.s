# Purpose: sys_mkdir syscall test, on success, a folder is created

    .text
    .globl _start

_start:
    {
        call init
    }
# Create a new folder
	{
        r0=#387
        r1=##.L.str
	}
	{
        trap0(#0)
	}
    {
        p0 = cmp.eq(r0, #0); if (p0.new) jump:t pass
        jump fail
    }

.data

.L.str:
	.string	"./mkdir_test_folder"
	.size	.L.str, 18

.L.buf1:
    .skip 4

.L.buf2:
    .skip 4
