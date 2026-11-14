"""
Task 4(b) - HMAC-SHA256 over the same message with a shared secret key.
HMAC(K, m) = H((K xor opad) || H((K xor ipad) || m)).
The receiver recomputes the tag: it matches for m1 but not for the altered m2.
"""
import hashlib, hmac

m1 = b"Patient: John Doe, Diagnosis: MCI"
m2 = b"Patient: John Doe, Diagnosis: MCT"

key = b"clinic-hospital-shared-secret"

tag1 = hmac.new(key, m1, hashlib.sha256).hexdigest()
tag2 = hmac.new(key, m2, hashlib.sha256).hexdigest()

print("(b) HMAC(m1):", tag1)
print("HMAC(m2):", tag2)
print("Receiver check on m1 :", hmac.compare_digest(tag1, hmac.new(key, m1, hashlib.sha256).hexdigest()))
print("Receiver check on m2 :", hmac.compare_digest(tag1, hmac.new(key, m2, hashlib.sha256).hexdigest()))
