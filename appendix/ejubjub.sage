JUBJUB_C = 8		# Cofactor
JUBJUB_A = 168700	# Coefficient A
JUBJUB_D = 168696	# Coefficient D
MONT_A = 168698
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
Fp = GF(p)
E = EllipticCurve(Fp, [0, MONT_A, 0, 1, 0])
G = E.gens()

assert E.order() == 21888242871839275222246405745257275088614511777268538073601725287587578984328
assert E.quadratic_twist().order() == 21888242871839275222246405745257275088482217023563530613794683085564038006908
# factor(E.quadratic_twist().order()) == 2^2 * 5472060717959818805561601436314318772120554255890882653448670771391009501727

assert E.trace_of_frobenius() not in [0, 1]

twistCofactor = 4
curveCofactor = 8

curveOrder = E.order()

twistOrder = 2 * (p+1) - curveOrder
assert E.quadratic_twist().order() == twistOrder
assert is_prime(twistOrder // twistCofactor)
assert is_prime(E.order() // curveCofactor)

jubjub_valid = lambda x, y: (JUBJUB_A * x^2 + y^2) == 1 + JUBJUB_D * x^2 * y^2
mont_valid = lambda x, y: E.is_on_curve(x, y)
mont_to_jubjub = lambda x, y: (x/y, (x-1)/(x+1))

Bx, By, Bz = G[0]

(u0, v0) = mont_to_jubjub(Bx, By)
