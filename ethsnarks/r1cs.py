from py_ecc.bn128 import curve_order

def r1cs_constraint(a, b, c):
    assert ((((a * b) % curve_order) - c) % curve_order) == 0
