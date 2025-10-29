from bitarray import bitarray

def Bitarray(b) -> bitarray:
    if type(b) == bytes:
        if len(b) != 1:
            print("Expecting Byte, received more or less")
            exit(-1)
        temp = bitarray(endian='big')
        temp.frombytes(b)
        return temp
    elif type(b) == int:
        b %= 2**8
        return Bitarray(b.to_bytes(1, byteorder='big'))
    else:
        print("Error")
        return bitarray(0)
Byte = Bitarray

def Word():
    pass

def toInt(a: bitarray) -> int:
    s, a = 0, a.copy()
    # Same effect can be brought by reversing the array beforehand
    for i in range(len(a)):
        s += a[len(a) - i - 1] * (2**i)
    return s

def shiftRight(word: bitarray, times=1):
    #if len(word) != 8:
    #    print("Error: Non a byte")
    #    print(word, len(word))
    #    exit(-2)
    return word.copy() >> times #(times % 8)

def shiftLeft(word: bitarray, times=1):
    #if len(word) != 8:
    #    print("Error: Not a byte")
    #    exit(-2)
    return word.copy() << times #(times % 8)

def rotateRight(word: bitarray, times=1):
    #times %= 8

    temp1 = shiftRight(word, times)
    temp2 = shiftLeft(word, len(word) - times)

    return temp1 | temp2

def rotateLeft(word: bitarray, times=1):
    #times %= 8
    return rotateRight(word, len(word) - times)

def XOR(oper1, oper2)->bitarray:
    return oper1 ^ oper2