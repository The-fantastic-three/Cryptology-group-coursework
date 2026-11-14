"""
Task 5(e) - Why Reed-Solomon codes are used in QR codes and CDs.
RS works on bytes (symbols), so one damaged byte counts as ONE symbol error
however many of its 8 bits are wrong. That is why it handles burst errors
(a scratch on a CD, a smudge on a QR code) far better than bit-level codes.
Here 10 parity bytes can correct up to 5 corrupted bytes.
Needs:  pip install reedsolo
"""
from reedsolo import RSCodec

rsc = RSCodec(10)                       # 10 parity bytes -> corrects up to 5 byte errors
message = b"MRI ready for review"
encoded = bytearray(rsc.encode(message))
print("Encoded length:", len(encoded), "bytes (", len(message), "data +", len(encoded) - len(message), "parity )")

# a burst error: 4 consecutive bytes destroyed (like a scratch)
for i in range(3, 7):
    encoded[i] ^= 0xFF
print("Corrupted burst of 4 bytes (32 bits)")

decoded = rsc.decode(bytes(encoded))[0]
print("Recovered:", decoded)
assert decoded == message
