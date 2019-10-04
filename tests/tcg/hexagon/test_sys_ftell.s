# Purpose: sys_ftell syscall test, on success, the position inside the file is returned

    .text
    .globl _start
    .set len, 20

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
        r2=#len
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
# Initial position should be 0
    {
        r28=r0
        memw(r29+#0)=r0
    }
    {
        r0=#256
        r1=r29
    }
    {
        trap0(#0)
    }
    {
        p0 = cmp.eq(r0, #0); if (p0.new) jump:t test2
        jump fail
    }

test2:
# Read a single character through sys_read
    {
        memw(r29+#0)=r28
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
# Now the position should be 1
    {
        memw(r29+#0)=r28
    }
    {
        r0=#256
        r1=r29
    }
    {
        trap0(#0)
    }
    {
        p0 = cmp.eq(r0, #1); if (p0.new) jump:t pass
        jump fail
    }

.data

.L.str:
	.string	"./test_sys_ftell.tst"
	.size	.L.str, len

.L.buf1:
    .skip 4

.L.buf2:
    .skip 4
