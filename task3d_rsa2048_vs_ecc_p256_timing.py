"""
Task 3(d) - Quick timing for the RSA-2048 vs ECC P-256 comparison
(key generation, signing, verification, signature size). Times are averages
in milliseconds and will differ from machine to machine.
"""
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import hashes

data = b"x" * 100


def avg_ms(f, k):
    t = time.perf_counter()
    for _ in range(k):
        f()
    return (time.perf_counter() - t) / k * 1000


# ---- RSA-2048 ----
rsa_kg = avg_ms(lambda: rsa.generate_private_key(65537, 2048), 5)
rk = rsa.generate_private_key(65537, 2048)
pss = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH)
rs = rk.sign(data, pss, hashes.SHA256())
rsa_sg = avg_ms(lambda: rk.sign(data, pss, hashes.SHA256()), 50)
rsa_vf = avg_ms(lambda: rk.public_key().verify(rs, data, pss, hashes.SHA256()), 50)

# ---- ECC P-256 ----
ec_kg = avg_ms(lambda: ec.generate_private_key(ec.SECP256R1()), 50)
ek = ec.generate_private_key(ec.SECP256R1())
es = ek.sign(data, ec.ECDSA(hashes.SHA256()))
ec_sg = avg_ms(lambda: ek.sign(data, ec.ECDSA(hashes.SHA256())), 50)
ec_vf = avg_ms(lambda: ek.public_key().verify(es, data, ec.ECDSA(hashes.SHA256())), 50)

print("(d) Timing in ms (average)      keygen    sign   verify")
print("RSA-2048                     %7.2f %7.2f %8.3f" % (rsa_kg, rsa_sg, rsa_vf))
print("ECC P-256                    %7.2f %7.2f %8.3f" % (ec_kg, ec_sg, ec_vf))
print("Signature sizes: RSA =", len(rs), "bytes, ECDSA =", len(es), "bytes (DER)")
