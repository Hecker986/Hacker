from hashlib import sha1
from math import *


def bin_to_hex(b: str):
    lb = len(b)
    if lb == 0:
        return ""
    return hex(int(b, 2))[2:].rjust(lb // 4, "0")


def hex_to_bin(h: str):
    lh = len(h)
    if lh == 0:
        return ""
    return bin(int(h, 16))[2:].rjust(4 * lh, "0")


def hash_sha1(h: str):
    return sha1(bytearray.fromhex(h)).hexdigest()


def bytes_to_hex(byte: bytes):
    if byte == b"":
        return ""
    else:
        lbt = len(byte)
        M = hex(int.from_bytes(byte, "big"))[2:].rjust(2 * lbt, "0")
        return M


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


class PSS(object):
    def __init__(self, n, emBits):
        self.n = n
        self.embits = emBits
        self.emlen = ceil(emBits / 8)
        self.slen = 20
        self.hlen = 20

    def MGF(self, X, masklen):
        T = ""
        k = ceil(masklen / self.hlen) - 1
        for cnt in range(k + 1):
            C = hex(cnt)[2:].rjust(8, "0")
            T += hash_sha1(X + C)
        mask = T[: 2 * masklen]
        return mask

    def Sign(self, M, d, salt):
        M = bytes_to_hex(M)
        mHash = hash_sha1(M)
        M1 = "0" * 16 + mHash + salt
        H = hash_sha1(M1)
        padding2 = (self.emlen - self.slen - self.hlen - 2) * "00" + "01"
        DB = padding2 + salt
        dbMask = self.MGF(H, self.emlen - self.hlen - 1)
        maskedDB = bin(int(DB, 16) ^ int(dbMask, 16))[2:].rjust(4 * len(dbMask), "0")
        maskedDB = (
            "0" * (8 * self.emlen - self.embits)
            + maskedDB[8 * self.emlen - self.embits :]
        )
        maskedDB = bin_to_hex(maskedDB)
        EM = maskedDB + H + "bc"
        m = int(EM, 16)
        s = quick_pow(m, d, self.n)
        return hex(s)[2:].rjust(256, "0")

    def Vrfy(self, M, e, S):
        s = int(S, 16)
        m = quick_pow(s, e, self.n)
        EM = hex(m)[2:].rjust(2 * self.emlen, "0")
        M = bytes_to_hex(M)
        mHash = hash_sha1(M)
        if self.emlen < self.hlen + self.slen + 2:
            return False
        if EM[-2:] != "bc":
            return False
        maskedDB = EM[: 2 * (self.emlen - self.hlen - 1)]
        H = EM[2 * (self.emlen - self.hlen - 1) : 2 * (self.emlen - 1)]
        maskedDB = hex_to_bin(maskedDB)
        if maskedDB[: 8 * self.emlen - self.embits] != "0" * (
            8 * self.emlen - self.embits
        ):
            return False
        dbMask = self.MGF(H, self.emlen - self.hlen - 1)
        DB = int(maskedDB, 2) ^ int(dbMask, 16)
        DB = bin(DB)[2:].rjust(len(maskedDB))
        DB = "0" * (8 * self.emlen - self.embits) + DB[8 * self.emlen - self.embits :]
        DB = bin_to_hex(DB)
        padding2 = (self.emlen - self.slen - self.hlen - 2) * "00" + "01"
        if DB[: 2 * (self.emlen - self.hlen - self.slen - 1)] != padding2:
            return False
        salt = DB[-self.slen * 2 :]
        M1 = "0" * 16 + mHash + salt
        H1 = hash_sha1(M1)
        if H == H1:
            return True
        else:
            return False


from pycallgraph import PyCallGraph
from pycallgraph.output import GraphvizOutput

if __name__ == "__main__":
    graphviz = GraphvizOutput()
    graphviz.output_file = "RSA-PSS数字签名算法.png"
    with PyCallGraph(output=graphviz):
        M = input().encode("utf-8")
        n = int(input())
        emBits = int(input())
        pss = PSS(n, emBits)
        Mode = input().strip()
        if Mode == "Sign":
            d = int(input())
            salt = input().strip()
            S = pss.Sign(M, d, salt)
            print(S)
        elif Mode == "Vrfy":
            e = int(input())
            S = input().strip()
            judge = pss.Vrfy(M, e, S)
            print(judge)
