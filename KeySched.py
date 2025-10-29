from Camellia_Components import *

# Constants for the key schedule, as described in 3.4:
Sigma1 = Bitarray_64(0xA09E667F3BCC908B)
Sigma2 = Bitarray_64(0xB67AE8584CAA73B2)
Sigma3 = Bitarray_64(0xC6EF372FE94F82BE)
Sigma4 = Bitarray_64(0x54FF53A5F1D36F1C)
Sigma5 = Bitarray_64(0x10E527FADE682D1D)
Sigma6 = Bitarray_64(0xB05688C2B3E6C1FD)

# Key Schedule for 128 bits of key size
# 3.4:
#def KeySchedule_128(key: bitarray)->bitarray:
def processRawKey(key: bitarray):
    if len(key) != 128:
        print("Key in key schedule not of correct size!")
        exit(-1)
        return

    # Init KeyL, KeyR
    KeyL = key
    KeyR = bitarray("0" * 128)

    # Init halves of KeyR, KeyL
    #t1 = split2Words(temp, 64)
    #KeyLL, KeyLR = t1[L], t1[R]
    #KeyRL, KeyRR = bitarray("0" * 64), bitarray("0" * 64)

    # XOR L and R
    temp = KeyL ^ KeyR

    # Convert temp(128 bits) into two halves of 64 bits
    left, right = splitBlock(temp)

    # Start Feistel Cipher
    #   # Encrypt temp two times with respective constants
    left, right = FesitelRound(left, right, Sigma1)
    left, right = FesitelRound(left, right, Sigma2)

    # After two rounds, XOR once more with KeyL
    left.extend(right)
    left ^= KeyL
    left, right = splitBlock(left)

    # Encrypt left||right two times with respective constants
    left, right = FesitelRound(left, right, Sigma3)
    left, right = FesitelRound(left, right, Sigma4)

    # After two more rounds, XOR once more with KeyR, extract KeyA
    left.extend(right)

    KeyA = left
    return KeyA, KeyL

    ##left ^= KeyR
    ##left, right = splitBlock(left)
    ### Encrypt left||right two times with respective constants
    ##left, right = FesitelRound(left, right, Sigma5)
    ##left, right = FesitelRound(left, right, Sigma6)
    ### Extract KeyB
    ##left.extend(right)
    ##KeyB = left.copy()
    
def makeRoundKeys(KeyA:bitarray, KeyL: bitarray, KeyB=None):
    if len(KeyL) != len(KeyA) != 128:
        print("In making round keys, KeyL or KeyA not 128 bits")
        exit(-1)
        return
    keys = []
    
    # KeyL Decomposition
    KeyLL, KeyLR = splitBlock(KeyL)
    KeyAL, KeyAR = splitBlock(KeyA)

    # Prewhitening Keys
    ## kw1, kw2
    keys.append(LeftPart(KeyL))
    keys.append(RightPart(KeyL))

    # Round 1, 2
    keys.append(LeftPart(KeyA)) # 1
    keys.append(RightPart(KeyA)) # 2

    # Rounds 3 - 6
    keys.append(LeftPart(rotateLeft(KeyL, 15))) # 3
    keys.append(RightPart(rotateLeft(KeyL, 15))) # 4

    keys.append(LeftPart(rotateLeft(KeyA, 15))) # 5
    keys.append(RightPart(rotateLeft(KeyA, 15))) # 6

    # FL, FL Inverse (Post Round 6)
    keys.append(LeftPart(rotateLeft(KeyA, 30))) # FL
    keys.append(RightPart(rotateLeft(KeyA, 30))) # FL Inverse

    # Rounds 7 - 12
    keys.append(LeftPart(rotateLeft(KeyL, 45))) # 7
    keys.append(RightPart(rotateLeft(KeyL, 45))) # 8

    keys.append(LeftPart(rotateLeft(KeyA, 45))) # 9
    keys.append(RightPart(rotateLeft(KeyL, 60))) # 10

    keys.append(LeftPart(rotateLeft(KeyA, 60))) # 11
    keys.append(RightPart(rotateLeft(KeyA, 60))) # 12

    # FL, FL Inverse (Post Round 12)
    keys.append(LeftPart(rotateLeft(KeyL, 77))) # FL
    keys.append(RightPart(rotateLeft(KeyL, 77))) # FL Inverse

    # Rounds 13 - 18
    keys.append(LeftPart(rotateLeft(KeyL, 94))) # 13
    keys.append(RightPart(rotateLeft(KeyL, 94))) # 14

    keys.append(LeftPart(rotateLeft(KeyA, 94))) # 15
    keys.append(RightPart(rotateLeft(KeyA, 94))) # 16

    keys.append(LeftPart(rotateLeft(KeyL, 111))) # 17
    keys.append(RightPart(rotateLeft(KeyL, 111))) # 18

    # Post Whitening
    keys.append(LeftPart(rotateLeft(KeyA, 111))) # kw3
    keys.append(RightPart(rotateLeft(KeyA, 111))) # kw4
    
    return keys

def KeySchedule128(key: bitarray):
    A, L = processRawKey(key)
    return makeRoundKeys(A, L)



# 28/02/2023
# Finished processing raw keys to extract KeyA, KeyL, KeyR, KeyB.
# For next time, take KeyA, KeyL and with reference to table 2, finish adding to the list
# 18 round keys plus some more keys, take note of the rotation before taking the left/right
# parts.
#
#
