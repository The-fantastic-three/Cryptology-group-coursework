"""
Task 2(a) - AES-128 encryption of a 128-bit (16-byte) patient record block
using pycryptodome. Encrypts one block, then decrypts it to verify.
"""
import os
from Crypto.Cipher import AES

key = os.urandom(16)                      # 128-bit AES key
block = b"PATIENT_FOUR_MAL"[:16]          # exactly 16 bytes = 128 bits
assert len(block) == 16

cipher = AES.new(key, AES.MODE_ECB)       # one block only, so mode is irrelevant here
ciphertext = cipher.encrypt(block)

print("Key (hex)        :", key.hex())
print("Plaintext block  :", block.decode())
print("Ciphertext (hex) :", ciphertext.hex())

decrypted = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
print("Decrypted        :", decrypted.decode())
assert decrypted == block
