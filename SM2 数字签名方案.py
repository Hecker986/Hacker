from math import *


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


# 字节串转二进制串
def bytes_to_bin(byte: bytes):
    if byte == b"":
        return ""
    else:
        lbt = len(byte)
        M = bin(int.from_bytes(byte, "big"))[2:].rjust(8 * lbt, "0")
        return M


# 二进制串转字节串
def bin_to_bytes(s: str):
    if s == "":
        return b""
    if len(s) % 8 != 0:
        s = "0" * (8 - len(s) % 8) + s
    ls = len(s)
    h = hex(int(s, 2))[2:].rjust(ls // 4, "0")
    return bytes.fromhex(h)


# 十六进制串转二进制串
def hex_to_bin(h: str):
    lh = len(h)
    if lh == 0:
        return ""
    return bin(int(h, 16))[2:].rjust(4 * lh, "0")


# 二进制串转十六进制串
def bin_to_hex(b: str):
    lb = len(b)
    if lb == 0:
        return ""
    return hex(int(b, 2))[2:].rjust(lb // 4, "0")


class SM3:
    @staticmethod
    def padding(m: str):
        L0 = len(m)
        LL0 = bin(L0)[2:].rjust(64, "0")
        r = (448 - len(m)) % 512
        m += "1"
        if r == 0:
            m += 511 * "0"
        else:
            m += (r - 1) * "0"
        m += LL0
        return m

    @staticmethod
    def cls(m: int, k: int):
        tmp = bin(m)[2:].rjust(32, "0")
        return int(tmp[k:] + tmp[:k], 2)

    @classmethod
    def P0(cls, X: int):
        return X ^ (cls.cls(X, 9)) ^ (cls.cls(X, 17))

    @classmethod
    def P1(cls, X: int):
        return X ^ (cls.cls(X, 15)) ^ (cls.cls(X, 23))

    @staticmethod
    def FF(j, X, Y, Z):
        if 0 <= j <= 15:
            return X ^ Y ^ Z
        else:
            return (X & Y) | (X & Z) | (Y & Z)

    @staticmethod
    def GG(j, X, Y, Z):
        if 0 <= j <= 15:
            return X ^ Y ^ Z
        else:
            return (X & Y) | ((~X) & Z)

    @classmethod
    def expand(cls, b: str):
        W = []
        for j in range(0, 16):
            W.append(int(b[32 * j : 32 * j + 32], 2))
        for j in range(16, 68):
            W.append(
                cls.P1(W[j - 16] ^ W[j - 9] ^ (cls.cls(W[j - 3], 15)))
                ^ cls.cls(W[j - 13], 7)
                ^ W[j - 6]
            )
        W_ = []
        for j in range(64):
            W_.append(W[j] ^ W[j + 4])
        return W, W_

    @classmethod
    def CF(cls, v: str, b: str):
        W, W_ = cls.expand(b)
        A, B, C, D, E, F, G, H = (
            int(v[0:32], 2),
            int(v[32:64], 2),
            int(v[64:96], 2),
            int(v[96:128], 2),
            int(v[128:160], 2),
            int(v[160:192], 2),
            int(v[192:224], 2),
            int(v[224:256], 2),
        )
        T = [0x79CC4519] * 16 + [0x7A879D8A] * 48
        for j in range(64):
            SS1 = cls.cls((cls.cls(A, 12) + E + cls.cls(T[j], j % 32)) % 2**32, 7)
            SS2 = SS1 ^ (cls.cls(A, 12))
            TT1 = (cls.FF(j, A, B, C) + D + SS2 + W_[j]) % 2**32
            TT2 = (cls.GG(j, E, F, G) + H + SS1 + W[j]) % 2**32
            D = C
            C = cls.cls(B, 9)
            B = A
            A = TT1
            H = G
            G = cls.cls(F, 19)
            F = E
            E = cls.P0(TT2)
        A, B, C, D, E, F, G, H = (
            bin(A)[2:].rjust(32, "0"),
            bin(B)[2:].rjust(32, "0"),
            bin(C)[2:].rjust(32, "0"),
            bin(D)[2:].rjust(32, "0"),
            bin(E)[2:].rjust(32, "0"),
            bin(F)[2:].rjust(32, "0"),
            bin(G)[2:].rjust(32, "0"),
            bin(H)[2:].rjust(32, "0"),
        )
        return bin(int(A + B + C + D + E + F + G + H, 2) ^ int(v, 2))[2:].rjust(
            256, "0"
        )

    @classmethod
    def hash(cls, msg: bytes):
        m = bytes_to_bin(msg)
        m = cls.padding(m)
        B = []
        for i in range(0, len(m), 512):
            B.append(m[i : i + 512])
        n = len(m) // 512
        IV = 0x7380166F4914B2B9172442D7DA8A0600A96F30BC163138AAE38DEE4DB0FB0E4E
        V = []
        V.append(bin(IV)[2:].rjust(256, "0"))
        for i in range(0, n):
            V.append(cls.CF(V[i], B[i]))
        return V[-1]


class SM2:
    def __init__(
        self,
        p: int,
        a: int,
        b: int,
        n: int,
        Gx: int,
        Gy: int,
        IDA: str,
        xA: int,
        yA: int,
    ):
        self.p = p
        self.a = a
        self.b = b
        self.n = n
        self.Par = ceil(log2(p))
        self.Gx = Gx
        self.Gy = Gy
        self.IDA = IDA
        self.xA = xA
        self.yA = yA

    def P_add(self, Px, Py, Qx, Qy):
        if Px == Py and (Qx + Qy) % self.p == 0:
            return 0, 0
        elif Px == Py and Qx == Qy:
            lmd = (3 * Px**2 + self.a) * invmod(2 * Py, self.p) % self.p
        else:
            lmd = (Qy - Py) * invmod(Qx - Px, self.p) % self.p
        Rx = (lmd**2 - Px - Qx) % self.p
        Ry = (lmd * (Px - Rx) - Py) % self.p
        return Rx, Ry

    def double(self, Px, Py):
        lmd = (3 * Px**2 + self.a) * invmod(2 * Py, self.p) % self.p
        Rx = (lmd**2 - 2 * Px) % self.p
        Ry = (lmd * (Px - Rx) - Py) % self.p
        return Rx, Ry

    def P_mul(self, Px, Py, k: int):  # 蒙哥马利阶梯法
        if k == 0:
            return 0, 0
        elif k == 1:
            return Px, Py
        elif k % 2 == 1:
            x, y = self.P_mul(Px, Py, k - 1)
            return self.P_add(Px, Py, x, y)
        else:
            x, y = self.double(Px, Py)
            return self.P_mul(x, y, k // 2)

    def to_bits(self, a: int):
        return bin(a)[2:].rjust(self.Par, "0")

    def get_Z(self):
        IDA = bytes_to_bin(self.IDA.encode("utf-8"))
        ENTL_A = bin(len(IDA))[2:].rjust(16, "0")
        aa = self.to_bits(self.a)
        bb = self.to_bits(self.b)
        xG = self.to_bits(self.Gx)
        yG = self.to_bits(self.Gy)
        xA = self.to_bits(self.xA)
        yA = self.to_bits(self.yA)
        tmp = bin_to_bytes(ENTL_A + IDA + aa + bb + xG + yG + xA + yA)
        ZA = SM3.hash(tmp)
        return bin_to_bytes(ZA)

    def Sign(self, M, dA, K):
        ZA = self.get_Z()
        M1 = ZA + M.encode("utf-8")
        e = int(SM3.hash(M1), 2)
        x1, y1 = self.P_mul(self.Gx, self.Gy, K)
        r = (e + x1) % self.n
        s = invmod(1 + dA, self.n) * (K - r * dA) % self.n
        return r, s

    def Vrfy(self, M, r, s):
        ZA = self.get_Z()
        M1 = ZA + M.encode("utf-8")
        e = int(SM3.hash(M1), 2)
        t = (r + s) % self.n
        sGx, sGy = self.P_mul(self.Gx, self.Gy, s)
        tPx, tPy = self.P_mul(self.xA, self.yA, t)
        x1, x2 = self.P_add(sGx, sGy, tPx, tPy)
        R = (e + x1) % self.n
        return R == r


from pycallgraph import PyCallGraph
from pycallgraph.output import GraphvizOutput

if __name__ == "__main__":
    graphviz = GraphvizOutput()
    graphviz.output_file = "SM2数字签名方案.png"
    with PyCallGraph(output=graphviz):
        p = int(input())
        a = int(input())
        b = int(input())
        Gx, Gy = map(int, input().split())
        n = int(input())
        IDA = input().strip()
        xA, yA = map(int, input().split())
        sm2 = SM2(p, a, b, n, Gx, Gy, IDA, xA, yA)
        M = input().strip()
        Mode = input().strip()
        if Mode == "Sign":
            dA = int(input())
            K = int(input())
            r, s = sm2.Sign(M, dA, K)
            print(r)
            print(s)
        elif Mode == "Vrfy":
            r = int(input())
            s = int(input())
            judge = sm2.Vrfy(M, r, s)
            print(judge)
