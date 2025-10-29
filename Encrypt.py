from KeySched import KeySchedule128
from Camellia_Components import *

def Camellia128Encrypt(message: bitarray, key: bitarray)->bitarray:
    if len(message) != len(key) != 128:
        print("Encryption: Key or message of wrong length!")
        exit(-1)
        return
    
    # Key Schedule + Block Init - Init round keys
    keys = KeySchedule128(key.copy())
    keys.insert(0, None)

    left, right = splitBlock(message.copy())

    # Keyed Pre-Whitening
    left ^=  keys[1]
    right ^= keys[2]

    # Rounds 1 - 6
    for Round in range(1, 7, 1):
        #print(Round + 2)
        left, right = FesitelRound(left, right, keys[Round + 2])

    # First Data Randomization
    left = FL_Func(left, keys[9])
    right = FL_Inverse(right, keys[10])

    # Rounds 7 - 12
    for Round in range(7, 13, 1):
        #print(Round + 4)
        left, right = FesitelRound(left, right, keys[Round + 4])

    # Second Data Randomization
    left = FL_Func(left, keys[17])
    right = FL_Inverse(right, keys[18])

    # Rounds 13 - 18
    for Round in range(13, 19, 1):
        #print(Round + 6)
        left, right = FesitelRound(left, right, keys[Round + 6])

    # Finale Swap
    left, right= right, left

    # Keyed Post-Whitening
    left ^=  keys[25]
    right ^= keys[26]
    
    # Delete Keys!
    for i in range(1, 27, 1):
        keys[i] = bitarray(45)
        keys[i].setall(0)

    ciphertext = left
    ciphertext.extend(right)
    return ciphertext


def Camellia128Decrypt(message: bitarray, key: bitarray):
    if len(message) != len(key) != 128:
        print("Decryption: Key or message of wrong length!")
        exit(-1)
        return
    
    # Key Schedule + Block Init - Init round keys
    keys = KeySchedule128(key)
        #keys = keys.reverse()
    keys.insert(0, None)

    left, right = splitBlock(message)

    ## Start
    # Inverse Keyed Post Whitening
    left  ^= keys[25]
    right ^= keys[26]
    
    # Rounds 18 - 13
    for Round in range(24, 18, -1):
        print(Round - 6)
        left, right = FesitelRound(left, right, keys[Round])

    # Inverse Second Data Randomization
    left = FL_Func(left, keys[18])      # Left FL kl4
    right = FL_Inverse(right, keys[17]) # Right InvFL kl3

    # Rounds 12 - 7
    for Round in range(16, 10, -1):
        print(Round - 4)
        left, right = FesitelRound(left, right, keys[Round])

    # Inverse First Data Randomization
    left = FL_Func(left, keys[10])      # Left FL kl2
    right = FL_Inverse(right, keys[9]) # Right InvFL kl1

    # Rounds 6 - 1
    for Round in range(8, 2, -1):
        print(Round - 2)
        left, right = FesitelRound(left, right, keys[Round])

    # Feistel Swap
    left, right = right, left

    # Inverse Keyed Pre Whitening
    left  ^= keys[1]
    right ^= keys[2]

    # Delete Keys!
    for i in range(1, 27, 1):
        keys[i] = bitarray(45)
        keys[i].setall(0)

    # Composition
    left.extend(right)
    return left


# Important Anecdotes for implementation
# 1. While Enc (and Dec), do not forget the final Feistel Swap.
# 2. Make sure that the For loop's index runs over all the rounds by printing each rounds number
#    The final mistake made by me for which I had to re-check the encryption process was that the first
#    For loop was not reaching round 13, and this completely wrecked my output -> Important part of 
#    implementation.
#
#
#



def archive():
    #test = blockFromInt(0x0123456789ABCDEFFEDCBA9876543210, 16)
    ##testKey2 = blockFromInt(0x0000000000000000, 16)
    ##testPT2  = blockFromInt(0x8000000000000000, 16)

    ###temp = blockFromInt(test, 16)
    ##print(hex(IntFromBlock(testPT2)))

    ###print(temp)

    ###ans = Camellia128Encrypt(temp, temp)
    ##ans2 = Camellia128Encrypt(testPT2, testKey2)
    ###ans2 = Camellia128Decrypt(ans, temp)

    ###print(ans2)
    ##print()

    #TK = [0xFF for i in range(16)]
    #TPT = [0x80]
    #for i in range(15):
    #    TPT.append(0)

    #key, pt = bytes(TK), bytes(TPT)
    #a, b = bitarray(), bitarray()
    #a.frombytes(pt)
    #b.frombytes(key)

    #print(hex(IntFromBlock(a)))
    #c = Camellia128Encrypt(a, b)
    #e = Camellia128Decrypt(c, b)
    ##d = c.tobytes()
    ##f = e.tobytes()
    #print(hex(IntFromBlock(e)))

    ##TK = [0 for i in range(16)]
    ##TPT = [0x80]
    ##for i in range(15):
    ##    TPT.append(0)

    ##key, pt = bytes(TK), bytes(TPT)
    ##a, b = bitarray(), bitarray()
    ##a.frombytes(pt)
    ##b.frombytes(key)

    ##c = Camellia128Encrypt(a, b)
    ##d = c.tobytes()
    ##print(hex(IntFromBlock(c)))
    return