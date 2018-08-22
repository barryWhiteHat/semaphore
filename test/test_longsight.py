import unittest

from random import randint

from ethsnarks.longsight import LongsightF, LongsightL, LongsightF322p5, curve_order

class MiMCTests(unittest.TestCase):
    def test_LongsightF_known1(self):
        x_L = 3703141493535563179657531719960160174296085208671919316200479060314459804651
        x_R = 134551314051432487569247388144051420116740427803855572138106146683954151557
        expected = 1955118202659622298192442035507501123132991419752400995882287708761535290053
        actual = LongsightF322p5(x_L, x_R)
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