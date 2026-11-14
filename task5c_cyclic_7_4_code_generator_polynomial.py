"""
Task 5(c) - (7,4) cyclic code with generator polynomial g(x) = x^3 + x + 1 (1011).
Systematic encoding: c(x) = x^3 m(x) + remainder of x^3 m(x) / g(x).
Message 1101 -> parity 001 -> codeword 1101001.
"""


def cyclic_74_encode(msg, g=[1, 0, 1, 1]):
    # msg is 4 bits
    shifted = msg + [0, 0, 0]           # multiply by x^3
    rem = list(shifted)
    for i in range(len(msg)):
        if rem[i] == 1:
            for j in range(len(g)):
                rem[i + j] ^= g[j]
    parity = rem[-3:]
    codeword = msg + parity
    return codeword, parity


if __name__ == "__main__":
    msg = [1, 1, 0, 1]
    cw, parity = cyclic_74_encode(msg)
    print(f"Message: {msg}")
    print(f"Computed Parity Bits: {parity}")
    print(f"Output Cyclic Codeword: {cw}")
    assert cw == [1, 1, 0, 1, 0, 0, 1]
