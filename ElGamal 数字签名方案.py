from hashlib import sha256


def quick_pow(a: int, b: int, m: int):
    i = 0
    s = []
    c = 1
    while b >= 1:
        s.append(b & 1)
        b = int(b // 2)
        i = i + 1
    for j in range(i - 1, -1, -1):
        if s[j] == 0:
            c = (c * c) % m
        else:
            c = (c * c * a) % m
    return c


# 欧几里得算法
def gcd(a: int, b: int):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


def gcdext(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = gcdext(b, a % b)
    return g, y, x - (a // b) * y


# 整数求模逆
def invmod(a: int, m: int):
    if gcd(a, m) != 1:
        raise ValueError
    _, b, _ = gcdext(a, m)
    return b % m


class ElGamlal:
    def __init__(self, q, a):
        self.q = q
        self.a = a

    def Sign(self, M, XA, K):
        m = int(sha256(M).hexdigest(), 16)
        S1 = quick_pow(self.a, K, self.q)
        S2 = invmod(K, self.q - 1) * (m - XA * S1) % (self.q - 1)
        return S1, S2

    def Vrfy(self, M, YA, S1, S2):
        m = int(sha256(M).hexdigest(), 16)
        V1 = quick_pow(self.a, m, self.q)
        V2 = quick_pow(YA, S1, self.q) * quick_pow(S1, S2, self.q) % self.q
        return V1 == V2


from pycallgraph import PyCallGraph
from pycallgraph.output import GraphvizOutput

if __name__ == "__main__":
    graphviz = GraphvizOutput()
    graphviz.output_file = "ElGamal数字签名方案.png"
    with PyCallGraph(output=graphviz):
        q = int(input())
        a = int(input())
        elg = ElGamlal(q, a)
        M = input().strip().encode("utf-8")
        Mode = input().strip()
        if Mode == "Sign":
            XA = int(input())
            K = int(input())
            s1, s2 = elg.Sign(M, XA, K)
            print(s1, s2)
        elif Mode == "Vrfy":
            YA = int(input())
            S1, S2 = map(int, input().split(" "))
            res = elg.Vrfy(M, YA, S1, S2)
            print(res)
