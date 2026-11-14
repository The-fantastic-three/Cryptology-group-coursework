"""
Task 3(b) - Encrypt M = 7 with the public key (7, 143) and decrypt with the
private key (103, 143) to verify correctness.   Expected: C = 6, M' = 7.
"""
n, e, d = 143, 7, 103
M = 7

C = pow(M, e, n)                  # C = M^e mod n
print(f"Encryption: C = {M}^{e} mod {n} = {C}")

M2 = pow(C, d, n)                 # M' = C^d mod n
print(f"Decryption: M' = {C}^{d} mod {n} = {M2}")

assert C == 6 and M2 == M
print("M' == M ->", M2 == M, "(RSA works)")
