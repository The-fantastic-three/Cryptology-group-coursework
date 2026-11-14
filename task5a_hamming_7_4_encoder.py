"""
Task 5(a) - Hamming (7,4) encoder (even parity).
Positions 1..7 = p1 p2 d1 p4 d2 d3 d4 (parity bits at positions 1, 2, 4).
Data word 1011 -> transmitted codeword 0110011.
"""


def hamming_encode(d):
    d1, d2, d3, d4 = d
    p1 = d1 ^ d2 ^ d4          # covers positions 1, 3, 5, 7
    p2 = d1 ^ d3 ^ d4          # covers positions 2, 3, 6, 7
    p4 = d2 ^ d3 ^ d4          # covers positions 4, 5, 6, 7
    return [p1, p2, d1, p4, d2, d3, d4]


if __name__ == "__main__":
    data = [1, 0, 1, 1]
    code = hamming_encode(data)
    print("Data word  :", "".join(map(str, data)))
    print("Code word sent :", "".join(map(str, code)))
    assert code == [0, 1, 1, 0, 0, 1, 1]
