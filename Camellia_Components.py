from Camellia_Base import *

# 4.1: F-Function, in addition see 4.4 and 4.6
def F_Func(X: bitarray, k: bitarray)->bitarray:
    if len(X) != len(k) != 64:
        print("F Function argument not 64 bits")
        exit(-1)
        return
    return P_Func( S_Func( X ^ k ) )

#4.2: FL_Function
def FL_Func(X: bitarray, k: bitarray)->bitarray:
    if len(X) != len(k) != 64:
        print("F Function argument not 64 bits")
        exit(-1)
        return
    Y = []
    R, L = 1, 0

    X = split2Words(X, 32)
    k = split2Words(k, 32)

    Yr, Yl = bitarray(), bitarray()
    Yr = rotateLeft((X[L] & k[L])) ^ X[R]
    Yl = (Yr | k[R]) ^ X[L]

    Yl.extend(Yr)
    return Yl

#4.3: Inverse FL_Function described in 4.2
def FL_Inverse(Y: bitarray, k: bitarray)->bitarray:
    if len(Y) != len(k) != 64:
        print("F Function argument not 64 bits")
        exit(-1)
        return
    X = []
    R, L = 1, 0

    Y = split2Words(Y, 32)
    k = split2Words(k, 32)

    Xr, Xl = bitarray(), bitarray()
    Xl = (Y[R] | k[R]) ^ Y[L]
    Xr = rotateLeft((Xl & k[L])) ^ Y[R]

    Xl.extend(Xr)
    return Xl


# 4.4: S-Function, part of the F-Function
def S_Func(L: bitarray)->bitarray:
    if len(L) != 64:
        print("S Function argument not 64-bit long")
        exit(-1)
    t = split2Words(L, 8)

    t[0] = sbox_1(t[0])
    t[1] = sbox_2(t[1])
    t[2] = sbox_3(t[2])
    t[3] = sbox_4(t[3])
    t[4] = sbox_2(t[4])
    t[5] = sbox_3(t[5])
    t[6] = sbox_4(t[6])
    t[7] = sbox_1(t[7])
    
    return concatWords(t)

# 4.6: P-Function, part of the F-Function
def P_Func(L: bitarray)->bitarray:
    # Primary Check
    if len(L) != 64:
        print("P-Func argument not 64 bit long")
        exit(-1)
    
    # Block Decomposition
    z = split2Words(L, 8)
    # The following line of code is added to make sure that the index is in line with the
    # specification document
    z.insert(0,None)
    t = z.copy()

    # Definition, see 4.6 in spec
    t[1] = z[1] ^ z[3] ^ z[4] ^ z[6] ^ z[7] ^ z[8]
    t[2] = z[1] ^ z[2] ^ z[4] ^ z[5] ^ z[7] ^ z[8]
    t[3] = z[1] ^ z[2] ^ z[3] ^ z[5] ^ z[6] ^ z[8]
    t[4] = z[2] ^ z[3] ^ z[4] ^ z[5] ^ z[6] ^ z[7]

    t[5] = z[1] ^ z[2] ^ z[6] ^ z[7] ^ z[8]
    t[6] = z[2] ^ z[3] ^ z[5] ^ z[7] ^ z[8]
    t[7] = z[3] ^ z[4] ^ z[5] ^ z[6] ^ z[8]
    t[8] = z[1] ^ z[4] ^ z[5] ^ z[6] ^ z[7]
    
    t.pop(0)
    return concatWords(t)

def FesitelRound(left: bitarray, right: bitarray, key: bitarray):
    if len(left) != 64 or len(right) != 64 or len(key) != 64:
        print("Round Arguments not 64 bits each!")
        exit(-1)

    left, right = left.copy(), right.copy()
    right ^= F_Func(left, key)
    return right, left

def splitBlock(block: bitarray):
    if len(block) != 128:
        print("Block Size not 128 bits!")
        exit(-1)
        return
    return block[0:64], block[64:]

def LeftPart(block: bitarray)-> bitarray:
    return block[0:int(len(block) / 2)]

def RightPart(block: bitarray)-> bitarray:
    return block[int(len(block) / 2):]

#t = bitarray("0011")
#print(RightPart(t))
