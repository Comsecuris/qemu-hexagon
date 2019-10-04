# Purpose: sys_read syscall test, on success, the buffer is filled

    .text
    .globl _start

_start:
    {
        call init
    }
# sys_open syscall
    {
        allocframe(r29,#16):raw
    }
    {
        r0=##.L.str
    }
    {
        r1=#0
        memw(r29+#0)=r0
    }
    {
        r2=#18
        memw(r29+#4)=r1
    }
    {
        memw(r29+#8)=r2
    }
	{
        r0=#1  
        r1=r29
	}
	{
        trap0(#0)
	}
# sys_read syscall
    {
        memw(r29+#0)=r0
    }
    {
        r1=##.L.buf
        memw(r29+#4)=r1.new;
    }
    {
        r2=#32
        memw(r29+#8)=r2.new;
    }
    {
        r0=#6
        r1=r29
    }
    {
        trap0(#0)
    }
# compare the first read character, should be a capital 'T'
    {
        r0=memb(##.L.buf)
    }
    {
        p0 = cmp.eq(r0, #0x54); if (p0.new) jump:t pass
        jump fail
    }

.data

.L.str:
	.string	"./test_file.txt"
	.size	.L.str, 16

.L.buf:
    .skip 33
