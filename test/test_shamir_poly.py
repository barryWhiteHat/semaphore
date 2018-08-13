import unittest

from ethsnarks.shamirspoly import lagrange, shamirs_poly, randq, randn, shamirs_poly_n
from ethsnarks.r1cs import r1cs_constraint

from scipy.interpolate import lagrange as scipy_lagrange


def unzip(x):
    return [_[0] for _ in x], [_[1] for _ in x]


class ShamirPolyTests(unittest.TestCase):
    def test_fromdocs(self):
        p = 100003
        k = 4
        a = [6257, 85026, 44499, 14701]
        F = lambda i, x: a[i] * (x**i)
        X = lambda x: a[0] + F(1, x) + F(2, x) + F(3, x)
        # Create the shares
        Sx = range(1, 5)
        Sy = [X(_) for _ in Sx]
        for x, y in zip(Sx, Sy):
            print(x, y)
            z = shamirs_poly_n(x, a, p)
            assert z == y % p
        # Then recover secret
        assert a[0] == int(scipy_lagrange(Sx, Sy).c[-1])

    def test_fromdocs2(self):
        p = 100003
        k = 4
        a = [randn(p) for _ in range(0, k)] # [6257, 85026, 44499, 14701]
        F = lambda i, x: a[i] * (x**i)
        X = lambda x: a[0] + F(1, x) + F(2, x) + F(3, x)
        # Create the shares
        Sx = range(1, 5)
        Sy = [X(_) for _ in Sx]
        for x, y in zip(Sx, Sy):
            z = shamirs_poly_n(x, a, p)
            assert z == y % p
        # Then recover secret
        assert a[0] == int(scipy_lagrange(Sx, Sy).c[-1])

    def test_random(self):
        # Randomized tests
        for _ in range(0, 10):
            alpha = [randq() for _ in range(0, 4)]
            points = [(i, shamirs_poly(i, alpha))
                      for i in range(0, len(alpha))]
            assert alpha[0] == lagrange(points, 0)
            assert alpha[0] != lagrange(points[1:], 0)
            assert alpha[0] != lagrange(points[2:], 0)

    def test_random_small(self):
        q = 100003
        for _ in range(0, 10):
            alpha = [randn(q) for _ in range(0, 4)]
            points = [(i, shamirs_poly_n(i, alpha, q))
                      for i in range(0, len(alpha))]
            assert alpha[0] == lagrange(points, 0, q)
            assert alpha[0] != lagrange(points[1:], 0, q)
            assert alpha[0] != lagrange(points[2:], 0, q)

            # XXX: scipy's lagrange has floating point precision for large numbers
            points_x, points_y = unzip(points)
            interpolation = scipy_lagrange(points_x, points_y)
            assert int(interpolation.c[-1]) == alpha[0]

    def test_static(self):
        # Verify against static test vectors
        alpha = [6808181831819141657160280673506432691407806061837762993142662373500430825792,
                 4138536697521448323155976179625860582331141320072618244300034508091478437877,
                 20259243729221075783953642258755031830946498253783650311586175820530608751936,
                 11227115470523445882235139084890542822660569362938710556861479160600812964997]
        points = [(i, shamirs_poly(i, alpha)) for i in range(0, len(alpha))]
        test_points = [(0, 6808181831819141657160280673506432691407806061837762993142662373500430825792),
                       (1, 20544834857245836424258632451520592838797650598216707762192147676147522484985),
                       (2, 10833210933219706719196668784844423052753721417299010433393634464005858464330),
                       (3, 1259517139202877390892412692306630092142705895884865660519589327528699562575)]
        assert points == test_points
        assert alpha[0] == lagrange(points, 0)

    def test_poly_constraints(self):        
        I = 14107816444829002666153088737167870815199986768206359534115449255516606414458

        A = [
            17167899297711346731111134130539302906398306115120667361324654931060817769652,
            20692971555607562002131076139518972969954851288604992618106076572794460197154,
            11669314840495787582492056085422064523948780040073924653117253046363337959489,
            15735493254427804666818698471807230275586165984790760178845725782084556556535
        ]

        S = [
            1,
            14107816444829002666153088737167870815199986768206359534115449255516606414458,
            5067932324814081810415131337916762410698113547031307360925810907599032394672,
            13201723662860499519704937914604513230538757359894370890481138582074383924053
        ]

        T = [
            17167899297711346731111134130539302906398306115120667361324654931060817769652,
            13947767308050706262790594447202101821284419559667543268525874072511409211876,
            12611939459072476081893406313696501745859572890147944797422704733972764295239,
            1657398546220101661314129991806057074896482894269175421846876999103942041527
        ]

        assert shamirs_poly(I, A) == T[-1]

        for i in range(0, len(A)):
            if i == 0:
                r1cs_constraint(1, S[i], 1)
            elif i == 1:
                r1cs_constraint(I, I, S[i+1])
            elif i < (len(A)-1):
                r1cs_constraint(I, S[i], S[i+1])

            if i == 0:
                r1cs_constraint(A[i], S[i], T[i])
            else:
                r1cs_constraint(A[i], S[i], (T[i] - T[i-1]))


if __name__ == "__main__":
    unittest.main()
