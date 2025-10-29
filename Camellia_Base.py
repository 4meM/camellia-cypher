from Boolean_Funcs_V2 import *

# B: Byte - vector space of 1*B (8 bits)
# W: Word - vector space of 4*B (32 bits)
# L: Double word - vector space of 8*B (64 bits)
#
BLOCK_SIZE = 16
HALF_BLOCK = 8

R, L = 1, 0

# SBOX init
raw_sbox = [112,130,44,236,179,39,192,229,228,133,87,53,234,12,174,65,35,239,107,147,69,25,165,33,237,14,79,78,29,101,146,189,134,184,175,143,124,235,31,206,62,48,220,95,94,197,11,26,166,225,57,202,213,71,93,61,217,1,90,214,81,86,108,77,139,13,154,102,251,204,176,45,116,18,43,32,240,177,132,153,223,76,203,194,52,126,118,5,109,183,169,49,209,23,4,215,20,88,58,97,222,27,17,28,50,15,156,22,83,24,242,34,254,68,207,178,195,181,122,145,36,8,232,168,96,252,105,80,170,208,160,125,161,137,98,151,84,91,30,149,224,255,100,210,16,196,0,72,163,247,117,219,138,3,230,218,9,63,221,148,135,92,131,2,205,74,144,51,115,103,246,243,157,127,191,226,82,155,216,38,200,55,198,59,129,150,111,75,19,190,99,46,233,121,167,140,159,110,188,142,41,245,249,182,47,253,180,89,120,152,6,106,231,70,113,186,212,37,171,66,136,162,141,250,114,7,185,85,248,238,172,10,54,73,42,104,60,56,241,164,64,40,211,123,187,201,67,193,21,227,173,244,119,199,128,158]
sbox = []
for byte in raw_sbox:
    sbox.append(Bitarray(byte))
del(raw_sbox) # No need for raw sbox, as we need the bitarray version

def sbox_1(byte: bitarray):
    return sbox[toInt(byte)]

def sbox_2(byte: bitarray):
    return rotateLeft(sbox_1(byte))

def sbox_3(byte: bitarray):
    return rotateRight(sbox_1(byte))

def sbox_4(byte: bitarray):
    return sbox_1( rotateLeft(byte) )

# Aux Functions:
def split2Words(arg: bitarray, itemLen: int):
    ''' Splits 'arg' into blocks of size 'itemLen' '''
    t = []
    for i in range(0, len(arg), itemLen):
        t.append(arg[i:i+itemLen])
    return t

def concatWords(arg: iter):
    t = bitarray(0)
    for i in arg:
        t.extend(i)
    return t

def Bitarray_64(num: int)->bitarray:
    b = num.to_bytes(8, byteorder='big')
    t = bitarray()
    t.frombytes(b)
    return t

def blockFromInt(num: int, length = 16)->bitarray:
    ''' num is the number to be converted while length is the number of BYTES in a block '''
    if type(num) != int:
        raise Exception("Trying to convert non integer to block!")
    t = bitarray()
    t.frombytes(num.to_bytes(length, 'big'))
    return t
def IntFromBlock(block: bitarray)->int:
    if type(block) != bitarray:
        raise Exception("Trying to convert non bitarray block to integer!")

    b = bitarray(block).tobytes()
    return int.from_bytes(b, byteorder='big')