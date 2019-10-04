# Purpose: verify the soundness of several memory loads and stores
# 
# First fill up a buffer with known patterns:
# 0baabbccdd and 0x00112233, then test loads

# Set the buffer parameters:
# K = 0, I = 1; Length = 3
# M0 = 0000 0000 0000001 00000000000000011 = 131075
#     I(MSB) K    I(LSB)      Length
#
# C12 is CS0 and must be set to the start address of the circular buffer

    .text
    .globl _start

_start:
    {
        call init
    }
    {
        r1=#0
        r0=#131075
    }
    {
        m0 = r0
    }
    {
        r0=##buffer
    }
	{
        memw(r0) = #2864434397
    }
    {
        r1=memb(r0++#1)
    }
    {
        p0 = cmp.eq(r1, #4294967261); if (p0.new) jump:t test2
        jump fail
    }

test2:
    {
        r1=memb(r0++#1)
    }
    {
        p0 = cmp.eq(r1, #4294967244); if (p0.new) jump:t test3
        jump fail
    }

test3:
    {
        r0 = ##buffer
    }
    {
        c12 = r0
    }
    {
        r3=memb(r0++#1:circ(M0))
    }
    {
        r3=memb(r0++#1:circ(M0))
    }
    {
        r3=memb(r0++#1:circ(M0))
    }
    {
        r3=memb(r0++#1:circ(M0))
    }
    {
        p0 = cmp.eq(r3, #4294967261); if (p0.new) jump:t pass
        jump fail
    }

    .data
    .globl buffer
buffer:
    .space 32
    .size buffer, 32
