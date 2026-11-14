"""
Task 5(b) - Simulate a single-bit error in position 6 of the codeword 0110011,
compute the syndrome C4C2C1 and correct the error.
Expected: received 0110001, syndrome 110 (= 6), corrected 0110011, data 1011.
"""
from task5a_hamming_7_4_encoder import hamming_encode

data = [1, 0, 1, 1]
code = hamming_encode(data)


def syndrome(r):
    c1 = r[0] ^ r[2] ^ r[4] ^ r[6]     # positions 1,3,5,7
    c2 = r[1] ^ r[2] ^ r[5] ^ r[6]     # positions 2,3,6,7
    c4 = r[3] ^ r[4] ^ r[5] ^ r[6]     # positions 4,5,6,7
    return c4, c2, c1


received = code.copy()
received[6 - 1] ^= 1                    # flip position 6 (index 5)

c4, c2, c1 = syndrome(received)
pos = 4 * c4 + 2 * c2 + c1

print("Received        :", "".join(map(str, received)))
print("Syndrome C4C2C1 :", c4, c2, c1, "-> error position", pos)

if pos != 0:
    received[pos - 1] ^= 1              # correct the bit

print("Corrected word  :", "".join(map(str, received)))
print("Data recovered  :", received[2], received[4], received[5], received[6])
assert received == code and [received[2], received[4], received[5], received[6]] == data
