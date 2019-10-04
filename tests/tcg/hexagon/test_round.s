# Purpose: test example, verify the soundness of the cround operation
# 106 = 0b1101010 with the comma at third digit is 12.5 which is crounded to 12
# but rounded to 13

# 0b1100,1000
#    0b0,1000
#   if x == 0b1,1000
#       x+=1

# x += (extract(x, u-1, 1) | ((x << shamt)>>shamt) == 0b0,1000)) << (u-1)
# deposit(x, x, 0, u, u)

# if 

    .text
    .globl _start

_start:
    {
        call init
    }
	{
		r1=#200
	}
	{
        r2=round(r1, #4)
	}
    {
        p0 = cmp.eq(r2, #13); if (p0.new) jump:t test2
        jump fail
    }

test2:
    {
        r2=cround(r1, #4)
    }
    {
        p0 = cmp.eq(r2, #12); if (p0.new) jump:t pass
        jump fail
    }
