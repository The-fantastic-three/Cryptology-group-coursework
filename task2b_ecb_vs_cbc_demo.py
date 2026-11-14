"""
Task 2(b) - Difference between ECB and CBC modes on the same plaintext.
The plaintext is three identical 16-byte blocks. ECB gives three identical
ciphertext blocks (pattern leak); CBC (random IV) gives three different ones.
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad   # imported as in the report (not needed: 48 bytes is block-aligned)
import os

key = os.urandom(16)

plaintext = b'PATIENT_FOUR_MAL' * 3
print(f"Plaintext (48 bytes): {plaintext.decode()}\n")

# ---- ECB ----
cipher_ecb = AES.new(key, AES.MODE_ECB)
ciphertext_ecb = cipher_ecb.encrypt(plaintext)

print("==== ECB Ciphertext in 16-byte blocks ====")
print(f"Block 1: {ciphertext_ecb[0:16].hex()}")
print(f"Block 2: {ciphertext_ecb[16:32].hex()}")
print(f"Block 3: {ciphertext_ecb[32:48].hex()}")

# ---- CBC ----
cipher_cbc = AES.new(key, AES.MODE_CBC)
iv = cipher_cbc.iv
ciphertext_cbc = cipher_cbc.encrypt(plaintext)

print("\n==== CBC Ciphertext in 16-byte blocks ====")
print(f"IV (Hex): {iv.hex()}")
print(f"Block 1: {ciphertext_cbc[0:16].hex()}")
print(f"Block 2: {ciphertext_cbc[16:32].hex()}")
print(f"Block 3: {ciphertext_cbc[32:48].hex()}")
