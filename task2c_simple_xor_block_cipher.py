"""
Task 2(c) - One round of a simplified XOR-based block cipher.
P = 1011 0110, K = 1100 1010  ->  C = P XOR K = 0111 1100
"""
P = "10110110"
K = "11001010"

C = "".join(str(int(p) ^ int(k)) for p, k in zip(P, K))

print("P      =", P[:4], P[4:])
print("K      =", K[:4], K[4:])
print("P XOR K=", C[:4], C[4:])
print("Ciphertext block =", C[:4], C[4:])
assert C == "01111100"

# decryption check: (P XOR K) XOR K = P
back = "".join(str(int(c) ^ int(k)) for c, k in zip(C, K))
assert back == P
