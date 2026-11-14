"""
Task 3(e) - Stretch task: simplified Diffie-Hellman with p = 23, g = 5 and a
man-in-the-middle (MITM) attack by Eve.
Alice a = 4, Bob b = 3, Eve e = 6.
Result: Alice<->Eve share K = 2, Bob<->Eve share K = 6; Alice and Bob think
they share a key with each other, but Eve can read and re-encrypt everything.
"""
p, g = 23, 5
a, b, e = 4, 3, 6                      # private values of Alice, Bob, Eve

A = pow(g, a, p)                       # Alice's public value
B = pow(g, b, p)                       # Bob's public value
E = pow(g, e, p)                       # Eve's public value
print(f"Alice public A = {g}^{a} mod {p} = {A}")
print(f"Bob   public B = {g}^{b} mod {p} = {B}")
print(f"Eve   public E = {g}^{e} mod {p} = {E}")

# --- Normal (no attacker) exchange ---
k_alice = pow(B, a, p)
k_bob = pow(A, b, p)
print(f"\nNo attacker: Alice key = {k_alice}, Bob key = {k_bob}  (equal: {k_alice == k_bob})")

# --- Active MITM: Eve replaces A and B with E ---
print("\nMITM: Eve intercepts A and B and sends E to both sides")
K_alice = pow(E, a, p)                 # Alice thinks this is shared with Bob
K_eve_alice = pow(A, e, p)
K_bob = pow(E, b, p)                   # Bob thinks this is shared with Alice
K_eve_bob = pow(B, e, p)

print(f"Alice computes   E^a mod p = {E}^{a} mod {p} = {K_alice}")
print(f"Eve (with Alice) A^e mod p = {A}^{e} mod {p} = {K_eve_alice}")
print(f"Bob computes     E^b mod p = {E}^{b} mod {p} = {K_bob}")
print(f"Eve (with Bob)   B^e mod p = {B}^{e} mod {p} = {K_eve_bob}")

assert K_alice == K_eve_alice == 2
assert K_bob == K_eve_bob == 6
print("\nAlice and Bob end up with DIFFERENT keys; Eve knows both, so she can")
print("decrypt, modify and re-encrypt all traffic undetected.")
