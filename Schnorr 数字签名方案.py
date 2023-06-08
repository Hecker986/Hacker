from hashlib import sha1


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


class Schnorr(object):
    def __init__(self, p, q, a):
        self.p = p
        self.q = q
        self.a = a

    def Sign(self, M: str, s: int, r: int):
        x = quick_pow(self.a, r, self.p)
        e = int(sha1((M + str(x)).encode("utf-8")).hexdigest(), 16)
        y = (r + s * e) % self.q
        return e, y

    def Vrfy(self, M: str, v: int, e: int, y: int):
        r = quick_pow(self.a, y, self.p) * quick_pow(v, e, self.p) % self.p
        return int(sha1((M + str(r)).encode("utf-8")).hexdigest(), 16) == e


from pycallgraph import PyCallGraph
from pycallgraph.output import GraphvizOutput

if __name__ == "__main__":
    graphviz = GraphvizOutput()
    graphviz.output_file = "Schnorr数字签名方案.png"
    with PyCallGraph(output=graphviz):
        p = int(input())
        q = int(input())
        a = int(input())
        sch = Schnorr(p, q, a)
        M = input().strip()
        Mode = input().strip()
        if Mode == "Sign":
            s = int(input())
            r = int(input())
            e, y = sch.Sign(M, s, r)
            print(e, y)
        elif Mode == "Vrfy":
            v = int(input())
            e, y = map(int, input().split())
            judge = sch.Vrfy(M, v, e, y)
            print(judge)
