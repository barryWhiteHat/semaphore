from random import randint

from ethsnarks.mimc import LongsightF, LongsightL, curve_order

x_L = randint(1, curve_order-1)
x_R = randint(1, curve_order-1)
e = 5
R_F = 220
C_F = [randint(1, curve_order-1) for _ in range(0, R_F)]
R_L = 110
C_L = [randint(1, curve_order-1) for _ in range(0, R_L)]

print(LongsightF(x_L, x_R, C_F, R_F, e, curve_order))
print(LongsightL(x_L, C_L, R_L, e, curve_order))