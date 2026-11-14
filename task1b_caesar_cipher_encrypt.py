"""
Task 1(b) - Caesar cipher encryption with a shift of our choice (key = 3).
Plaintext = patient identifier (PATIENTTWELVE) + diagnosis code (MAL = malaria).
Formula: C = (P + key) mod 26, where A = 0, ..., Z = 25
Expected ciphertext: SDWLHQWWZHOYHPDO
"""

plaintext = "PATIENTTWELVEMAL"
key = 3

print(f"Plaintext = {plaintext}   Shift key = {key}")
print(f"{'Plain':<6}{'P':<4}{'P+key':<7}{'(P+key) mod 26':<16}Cipher")

ciphertext = ""
for ch in plaintext:
    p = ord(ch) - ord("A")
    shifted = p + key
    c = shifted % 26
    enc = chr(c + ord("A"))
    ciphertext += enc
    print(f"{ch:<6}{p:<4}{shifted:<7}{c:<16}{enc}")

print("\nEncrypted text =", ciphertext)
assert ciphertext == "SDWLHQWWZHOYHPDO"
