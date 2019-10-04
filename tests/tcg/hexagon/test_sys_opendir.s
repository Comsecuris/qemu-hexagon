# Purpose: sys_opendir syscall test, on success, a folder is first created then opened

    .text
    .globl _start

_start:
    {
        call init
    }
# Create a new folder
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
        r2=#16
        memw(r29+#4)=r1
    }
    {
        memw(r29+#8)=r2
    }
	{
        r0=#387
        r1=##.L.str
	}
    {
        r2=#4
        r3=#2
    }
	{
        trap0(#0)
	}
    {
        p0 = cmp.eq(r0, #0); if (p0.new) jump:t test2
        jump fail
    }

test2:
# Open a folder
    {
        allocframe(r29,#16):raw
    }
    {
        r0=##.L.str
    }
    {
        memw(r29+#0)=r0
    }
    {
        r2=#16
        memw(r29+#4)=r2.new
    }
	{
        r0=#384
        r1=r29
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
	.string	"./opendir_test_folder"
	.size	.L.str, 18

.L.buf1:
    .skip 4

.L.buf2:
    .skip 4
