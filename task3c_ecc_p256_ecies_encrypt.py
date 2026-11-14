"""
Task 3(c) - ECC key pair on curve P-256 and ECIES encryption of a short message.
The cryptography library has no ready-made ECIES function, so it is built from
standard parts: ephemeral ECDH -> HKDF-SHA256 -> AES-GCM.

Sender  : ephemeral P-256 key pair, ECDH(eph_priv, receiver_pub), HKDF -> AES key,
          AES-GCM encrypt -> send (ephemeral public key, nonce, ciphertext)
Receiver: ECDH(receiver_priv, eph_pub) gives the same secret -> same key -> decrypt
"""
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

priv = ec.generate_private_key(ec.SECP256R1())
pub = priv.public_key()                       # receiver's key pair

pub_bytes = pub.public_bytes(serialization.Encoding.X962,
                             serialization.PublicFormat.UncompressedPoint)
print("Receiver public key (65 bytes, hex):", pub_bytes.hex())


def make_key(shared_secret):
    return HKDF(algorithm=hashes.SHA256(), length=16, salt=None,
                info=b"ecies demo").derive(shared_secret)


def ecies_encrypt(receiver_pub, message):
    eph = ec.generate_private_key(ec.SECP256R1())              # fresh ephemeral key
    key = make_key(eph.exchange(ec.ECDH(), receiver_pub))      # ECDH -> HKDF -> AES key
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, message, None)
    return eph.public_key(), nonce, ct


def ecies_decrypt(receiver_priv, eph_pub, nonce, ct):
    key = make_key(receiver_priv.exchange(ec.ECDH(), eph_pub))
    return AESGCM(key).decrypt(nonce, ct, None)


msg = b"MRI ready for review"
eph_pub, nonce, ct = ecies_encrypt(pub, msg)

print("Plaintext        :", msg)
print("Ciphertext (hex) :", ct.hex())
print("Decrypted        :", ecies_decrypt(priv, eph_pub, nonce, ct))
