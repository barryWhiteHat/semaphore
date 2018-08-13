import unittest

from random import randint

from ethsnarks.mimc import LongsightF, LongsightL, LongsightF152p5, curve_order

class MiMCTests(unittest.TestCase):
    def test_LongsightF_known1(self):
        x_L = 21871881226116355513319084168586976250335411806112527735069209751513595455673
        x_R = 55049861378429053168722197095693172831329974911537953231866155060049976290
        expected = 11801552584949094581972187388927133931539817817986253233814495442311083852545
        actual = LongsightF152p5(x_L, x_R)
        #x_L = randint(1, curve_order-1)
        #x_R = randint(1, curve_order-1)
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()

"""
x_L = randint(1, curve_order-1)
x_R = randint(1, curve_order-1)
e = 5
R_F = 220
C_F = [randint(1, curve_order-1) for _ in range(0, R_F)]
R_L = 110
C_L = [randint(1, curve_order-1) for _ in range(0, R_L)]

print(LongsightF(x_L, x_R, C_F, R_F, e, curve_order))
print(LongsightL(x_L, C_L, R_L, e, curve_order))
"""