"""
Task 3(a) - RSA key generation with small primes p = 11 and q = 13.
Computes n, phi(n), chooses a valid e and finds d (modular inverse via the
extended Euclidean algorithm).  Expected: n=143, phi=120, e=7, d=103.
"""
from math import gcd


def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


p, q = 11, 13
n = p * q                         # Step 1: modulus
phi = (p - 1) * (q - 1)           # Step 2: Euler's totient

print(f"n = p x q = {p} x {q} = {n}")
print(f"phi(n) = (p-1)(q-1) = {p-1} x {q-1} = {phi}")

candidates = [e for e in range(2, phi) if gcd(e, phi) == 1]
print("Candidate coprimes for", phi, ":", candidates[:6])

e = 7                              # Step 3: chosen public exponent
assert gcd(e, phi) == 1
print(f"e = {e}  (gcd({e}, {phi}) = 1)")

g, x, _ = extended_gcd(e, phi)     # Step 4: d = e^-1 mod phi
d = x % phi
print(f"d = {d}   check: (e x d) mod phi = {(e * d) % phi}")
assert (e * d) % phi == 1

print(f"\nPublic key  (e, n) = ({e}, {n})")
print(f"Private key (d, n) = ({d}, {n})")
assert (n, phi, e, d) == (143, 120, 7, 103)
