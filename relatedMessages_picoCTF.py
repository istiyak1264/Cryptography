import sys

C1 = 3486364849772584627692611749053367200656673358261596068549224442954489368512244047032432842601611650021333218776410522726164792063436874469202000304563253268152374424792827960027328885841727753251809392141585739745846369791063025294100126955644910200403110681150821499366083662061254649865214441429600114378725559898580136692467180690994656443588872905046189428367989340123522629103558929469463071363053880181844717260809141934586548192492448820075030490705363082025344843861901475648208157572346004443100461870519699021342998731173352225724445397168276113254405106732294978648428026500248591322675321980719576323749
C2 = 201982790559548563915678784397933493721879152787419243871599124287434576744055997870874349538398878336345269929647585648144070475012256331468688792105087899416655051702630953882466457932737483198442642588375981620937494661378586614008496182135571457352400128892078765628319466855732569272509655562943410536265866312968101366413636251672211633011159836642751480632253423529271185888171036917413867011031963618529122680143291205470937752671602494831117301480813590683791618751348224964277861127486155552153012612562009905595646626759034581358425916638671884927506025703373056113307665093346439014722219878575598308124
N = 17334845546772507565250479697360218105827285681719530148909779921509619103084219698006014339278818598859177686131922807448182102049966121282308256054696565796008642900453901629937223685292142986689576464581496406676552201407729209985216274086331582917892470955265888718120511814944341755263650688063926284195007148056359887333784052944201212155189546062807573959105963160320187551755272391293705288576724811668369745107148481856135696249862795476376097454818009481550162364943945249601744881676746859305855091288055082626399929893610275614840617858985993338556889612804266896309310999363054134373435198031731045253881
e = 0x11
diff = -3

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def inverse(a, n):
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr
    if r > 1: return None
    if t < 0: t = t + n
    return t

class Poly:
    def __init__(self, coeffs):
        # coeffs is [c0, c1, c2, ...] where c_i is coeff of x^i
        while coeffs and coeffs[-1] % N == 0:
            coeffs.pop()
        self.coeffs = [c % N for c in coeffs]

    def __add__(self, other):
        res = [0] * max(len(self.coeffs), len(other.coeffs))
        for i in range(len(res)):
            c1 = self.coeffs[i] if i < len(self.coeffs) else 0
            c2 = other.coeffs[i] if i < len(other.coeffs) else 0
            res[i] = (c1 + c2) % N
        return Poly(res)

    def __sub__(self, other):
        res = [0] * max(len(self.coeffs), len(other.coeffs))
        for i in range(len(res)):
            c1 = self.coeffs[i] if i < len(self.coeffs) else 0
            c2 = other.coeffs[i] if i < len(other.coeffs) else 0
            res[i] = (c1 - c2) % N
        return Poly(res)

    def __mul__(self, other):
        if not self.coeffs or not other.coeffs:
            return Poly([])
        res = [0] * (len(self.coeffs) + len(other.coeffs) - 1)
        for i, c1 in enumerate(self.coeffs):
            for j, c2 in enumerate(other.coeffs):
                res[i+j] = (res[i+j] + c1 * c2) % N
        return Poly(res)

    def __mod__(self, other):
        if not other.coeffs:
            raise ZeroDivisionError()
        rem = list(self.coeffs)
        lc_inv = inverse(other.coeffs[-1], N)
        while len(rem) >= len(other.coeffs):
            deg_diff = len(rem) - len(other.coeffs)
            factor = (rem[-1] * lc_inv) % N
            for i in range(len(other.coeffs)):
                rem[deg_diff + i] = (rem[deg_diff + i] - factor * other.coeffs[i]) % N
            while rem and rem[-1] == 0:
                rem.pop()
        return Poly(rem)

    def monic(self):
        if not self.coeffs: return self
        lc_inv = inverse(self.coeffs[-1], N)
        return Poly([(c * lc_inv) % N for c in self.coeffs])

    def __pow__(self, p):
        res = Poly([1])
        base = self
        while p > 0:
            if p % 2 == 1:
                res = res * base
            base = base * base
            p //= 2
        return res

# g1 = (X + diff)^e - C1
# g2 = X^e - C2
X = Poly([0, 1])
g1 = (X + Poly([diff]))**e - Poly([C1])
g2 = X**e - Poly([C2])

# GCD using Euclidean algorithm
def poly_gcd(a, b):
    while b.coeffs:
        a, b = b, a % b
    return a.monic()

res = poly_gcd(g1, g2)
# res should be (X - m2)
# m2 = -res.coeffs[0]
m2 = (-res.coeffs[0]) % N

import binascii
m2_hex = hex(m2)[2:]
if len(m2_hex) % 2 != 0: m2_hex = '0' + m2_hex
print(f"flag: {binascii.unhexlify(m2_hex).decode()}")