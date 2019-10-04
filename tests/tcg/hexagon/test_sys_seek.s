# Purpose: sys_seek syscall test, on success, the same character is read twice

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
        r2=#16
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
# Read a single character through sys_read
    {
        r28=r0
        memw(r29+#0)=r0
    }
    {
        r1=##.L.buf1
        memw(r29+#4)=r1.new;
    }
    {
        r2=#1
        memw(r29+#8)=r2.new;
    }
    {
        r0=#6
        r1=r29
    }
    {
        trap0(#0)
    }
# Use sys_seek to rewind the open file
    {
        memw(r29+#0)=r28
    }
    {
        r1=#0
        memw(r29+#4)=r1.new;
    }
    {
        r0=#10
        r1=r29
    }
    {
        trap0(#0)
    }
# Read another character through sys_read
    {
        memw(r29+#0)=r28
    }
    {
        r1=##.L.buf2
        memw(r29+#4)=r1.new;
    }
    {
        r2=#1
        memw(r29+#8)=r2.new;
    }
    {
        r0=#6
        r1=r29
    }
    {
        trap0(#0)
    }
# compare the two read characters, should be a hash symbol
    {
        r0=memb(##.L.buf1)
        r1=memb(##.L.buf2)
    }
    {
        p0 = cmp.eq(r0, r1); if (p0.new) jump:t pass
        jump fail
    }

.data

.L.str:
	.string	"./test_sys_read.s"
	.size	.L.str, 18

.L.buf1:
    .skip 4

.L.buf2:
    .skip 4
