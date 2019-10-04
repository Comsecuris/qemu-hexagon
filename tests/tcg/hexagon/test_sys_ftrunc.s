# Purpose: sys_trunc syscall test, on success, the target file should change its size

    .text
    .globl _start

_start:
    {
        call init
    }
# Open a new file in write mode
    {
        allocframe(r29,#16):raw
    }
    {
        r0=##.L.str
    }
    {
        r1=#4
        memw(r29+#0)=r0
    }
    {
        r2=#22
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
# Extend the file to 64B
    {
        r28=r0
        memw(r29+#0)=r0
    }
    {
        r2=#64
        memw(r29+#4)=r2.new
    }
    {
        r0=#390
        r1=r29
    }
    {
        trap0(#0)
    }
# Check that file length is exactly 64B
    {
        memw(r29+#0)=r28
    }
	{
        r0=#12
        r1=r29
	}
	{
        trap0(#0)
	}
    {
        p0 = cmp.eq(r0, #64); if (p0.new) jump:t test2
        jump fail
    }

test2:
# Truncate the file to 12B
    {
        memw(r29+#0)=r28
    }
    {
        r2=#12
        memw(r29+#4)=r2.new
    }
    {
        r0=#390
        r1=r29
    }
    {
        trap0(#0)
    }
# Check that file length is exactly 12B
    {
        memw(r29+#0)=r28
    }
	{
        r0=#12
        r1=r29
	}
	{
        trap0(#0)
	}
    {
        p0 = cmp.eq(r0, #12); if (p0.new) jump:t pass
        jump fail
    }

.data

.L.str:
	.string	"./trunc_test_file.txt"
	.size	.L.str, 22

.L.buf1:
    .skip 4

.L.buf2:
    .skip 4
