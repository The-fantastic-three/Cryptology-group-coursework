"""
Task 4(a) - SHA-256 of "Patient: John Doe, Diagnosis: MCI" and of the same
message with a single character changed (I -> T). Shows the avalanche effect:
about half of the 256 output bits flip.
"""
import hashlib

m1 = b"Patient: John Doe, Diagnosis: MCI"
m2 = b"Patient: John Doe, Diagnosis: MCT"      # only the last character changed (I -> T)

h1 = hashlib.sha256(m1).hexdigest()
h2 = hashlib.sha256(m2).hexdigest()

print("(a) Message 1:", m1.decode()); print("SHA-256:", h1)
print("Message 2:", m2.decode()); print("SHA-256:", h2)

diff = bin(int(h1, 16) ^ int(h2, 16)).count("1")
print("Bits that differ:", diff, "out of 256 (%.1f%%)" % (diff / 256 * 100))
