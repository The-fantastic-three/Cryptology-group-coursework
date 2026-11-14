"""
Task 4(c) - Digital signature over a short report: RSA-2048 with PSS padding
and SHA-256. The report is hashed, the hash is signed with the private key and
verified with the public key. A one-character change makes verification fail.
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# 1. generating the key
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

report_data = b"Radiology Report: MRI scan shows no structural damage. Signed by Dr. Ocen."

pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

# 2. Signing
signature = private_key.sign(report_data, pss, hashes.SHA256())
print(f"Digital Signature (hex): {signature.hex()[:64]}...")


def verify(data):
    try:
        public_key.verify(signature, data, pss, hashes.SHA256())
        print("Signature Verification: SUCCESSFUL (Authentic & Unmodified)")
    except InvalidSignature as e:
        print(f"Signature Verification FAILED: {e!r}")


# 3. Verification
verify(report_data)

# 4. Tampered report (one character added) must fail
print("\nTampered report:")
verify(report_data + b"!")
