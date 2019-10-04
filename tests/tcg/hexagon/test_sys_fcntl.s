# Purpose: sys_fcntl syscall test, on success, the target command is executed

    .text
    .globl _start

_start:
    {
        call init
    }
# sys_open syscall
    {
        allocframe(r29,#32):raw
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
# sys_fcntl syscall to duplicate a file descriptor
    {
        r1=#0x40404040
        memw(r29+#0)=r1.new
    }
    {
        r1=#0x41414141
        memw(r29+#4)=r1.new
    }
    {
        r1=#0x42424242
        memw(r29+#8)=r1.new
    }
    {
        r1=#0x43434343
        memw(r29+#12)=r1.new
    }
# Parametri veri
    {
        memw(r29+#16)=r0
    }
    {
        r1=#0
        memw(r29+#20)=r1.new
    }
    {
        r1=add(r29, #16);
        memw(r29+#24)=r29;
    }
    {
        r0=#262
    }
    {
        trap0(#0)
    }
# compare the first read character, should be a hash symbol
    {
        r0=memb(##.L.buf)
    }
    {
        p0 = cmp.eq(r0, #35); if (p0.new) jump:t pass
        jump fail
    }

.data

.L.str:
	.string	"./test_sys_read.s"
	.size	.L.str, 18

.L.buf:
    .skip 33
