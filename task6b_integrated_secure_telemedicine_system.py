
import argparse
import hashlib
import hmac
import os
import random

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

IV_LEN = 16     # AES block size
MAC_LEN = 32    # HMAC-SHA256 tag
SIG_LEN = 64    # ECDSA P-256 signature as raw r || s (32 + 32 bytes)

CLINIC_TO_HOSPITAL = b"clinic->hospital"
HOSPITAL_TO_CLINIC = b"hospital->clinic"


class SecurityError(Exception):
    """Raised by the receiver when a message must be rejected."""



# Part 1: Hamming (7,4) error-correcting code (from Task 5)
# Codeword layout (positions 1..7):  p1 p2 d1 p4 d2 d3 d4   (even parity)

def hamming_encode_nibble(d1, d2, d3, d4):
    p1 = d1 ^ d2 ^ d4          # covers positions 1,3,5,7
    p2 = d1 ^ d3 ^ d4          # covers positions 2,3,6,7
    p4 = d2 ^ d3 ^ d4          # covers positions 4,5,6,7
    return [p1, p2, d1, p4, d2, d3, d4]


def hamming_decode_codeword(r):
    """Return (4 data bits, error position 0..7). 0 means no error found."""
    c1 = r[0] ^ r[2] ^ r[4] ^ r[6]
    c2 = r[1] ^ r[2] ^ r[5] ^ r[6]
    c4 = r[3] ^ r[4] ^ r[5] ^ r[6]
    pos = 4 * c4 + 2 * c2 + c1          # syndrome C4C2C1 as a number
    r = list(r)
    if pos:
        r[pos - 1] ^= 1                 # flip the faulty bit back
    return [r[2], r[4], r[5], r[6]], pos


def hamming_encode(data: bytes):
    """bytes -> list of bits (each byte becomes 2 codewords = 14 bits)."""
    bits = []
    for byte in data:
        for nibble in (byte >> 4, byte & 0x0F):
            d = [(nibble >> 3) & 1, (nibble >> 2) & 1, (nibble >> 1) & 1, nibble & 1]
            bits.extend(hamming_encode_nibble(*d))
    return bits


def hamming_decode(bits):
    """list of bits -> (bytes, list of (codeword_index, corrected_position))."""
    if len(bits) % 14 != 0:
        raise SecurityError("received block has an invalid length")
    nibbles, fixes = [], []
    for i in range(0, len(bits), 7):
        data, pos = hamming_decode_codeword(bits[i:i + 7])
        if pos:
            fixes.append((i // 7, pos))
        nibbles.append(data[0] << 3 | data[1] << 2 | data[2] << 1 | data[3])
    out = bytes((nibbles[i] << 4) | nibbles[i + 1] for i in range(0, len(nibbles), 2))
    return out, fixes



# Part 2: simulated noisy channel

def channel_flip_bits(bits, positions):
    """Flip exactly the listed bit positions (used for controlled tests)."""
    out = list(bits)
    for p in positions:
        out[p] ^= 1
    return out


def channel_random_noise(bits, ber, rng):
    """Flip every bit independently with probability `ber` (bit error rate)."""
    out, flipped = list(bits), []
    for i in range(len(out)):
        if rng.random() < ber:
            out[i] ^= 1
            flipped.append(i)
    return out, flipped



# Part 3: cryptographic sender / receiver

def derive_keys(session_key: bytes, direction: bytes):
    """Never use one key for two jobs: split the session key into an AES key
    and an HMAC key, separately for each direction (stops reflection attacks)."""
    material = HKDF(algorithm=hashes.SHA256(), length=48, salt=None,
                    info=b"telemed-v1|" + direction).derive(session_key)
    return material[:16], material[16:]       # 16-byte AES-128 key, 32-byte MAC key


def build_frame(plaintext: bytes, session_key: bytes, signing_key, direction: bytes):
    """Steps 1-6: encrypt, MAC, sign. Returns (frame_bytes, details)."""
    enc_key, mac_key = derive_keys(session_key, direction)

    iv = os.urandom(IV_LEN)                                       # fresh random IV
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    tag = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()   # encrypt-then-MAC

    digest = hashlib.sha256(plaintext).digest()                   # message digest
    der_sig = signing_key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(der_sig)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")     # fixed 64 bytes

    frame = iv + ciphertext + tag + signature
    details = {"iv": iv, "ciphertext": ciphertext, "tag": tag,
               "digest": digest, "signature": signature}
    return frame, details


def send(plaintext, session_key, signing_key, direction):
    """Full sender: build the frame and Hamming-encode it for transmission."""
    frame, details = build_frame(plaintext, session_key, signing_key, direction)
    tx_bits = hamming_encode(frame)
    details["frame_len"] = len(frame)
    details["tx_bits"] = len(tx_bits)
    return tx_bits, details


def receive(rx_bits, session_key, sender_public_key, direction):
    """Full receiver. Returns (plaintext, hamming_fixes) or raises SecurityError."""
    # 1. error correction (Hamming)
    frame, fixes = hamming_decode(rx_bits)
    if len(frame) < IV_LEN + 16 + MAC_LEN + SIG_LEN:
        raise SecurityError("frame too short")
    iv = frame[:IV_LEN]
    ciphertext = frame[IV_LEN:-(MAC_LEN + SIG_LEN)]
    tag = frame[-(MAC_LEN + SIG_LEN):-SIG_LEN]
    signature = frame[-SIG_LEN:]
    if len(ciphertext) % 16 != 0:
        raise SecurityError("ciphertext length is not a multiple of the AES block size")

    enc_key, mac_key = derive_keys(session_key, direction)

    # 2. verify MAC BEFORE decrypting (integrity + shared-key authentication)
    expected = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise SecurityError("HMAC verification FAILED (message altered or wrong key)")

    # 3. decrypt
    try:
        decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        raise SecurityError("decryption failed (bad padding)")

    # 4. verify digital signature over the SHA-256 digest of the plaintext
    digest = hashlib.sha256(plaintext).digest()
    der_sig = utils.encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                         int.from_bytes(signature[32:], "big"))
    try:
        sender_public_key.verify(der_sig, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    except InvalidSignature:
        raise SecurityError("signature verification FAILED (not signed by the claimed sender)")

    return plaintext, fixes



# Part 4: demonstration / testing

def banner(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def attempt(label, rx_bits, session_key, pub, direction, original):
    """Run the receiver and print a readable result."""
    try:
        plaintext, fixes = receive(rx_bits, session_key, pub, direction)
    except SecurityError as e:
        print(f"[{label}] RESULT: REJECTED -> {e}")
        return False
    ok = plaintext == original
    print(f"[{label}] Hamming corrected {len(fixes)} bit error(s)", end="")
    if fixes:
        shown = ", ".join(f"codeword {c} pos {p}" for c, p in fixes[:5])
        print(f" ({shown}{' ...' if len(fixes) > 5 else ''})", end="")
    print()
    print(f"[{label}] HMAC OK, signature OK, plaintext matches original: {ok}")
    return ok


def main():
    ap = argparse.ArgumentParser(description="BCS 2104 Task 6 secure telemedicine demo")
    ap.add_argument("--message", default="Patient: PATIENT_TWELVE; Dx code: MAL; "
                    "MRI brain attached; please review urgently.")
    ap.add_argument("--seed", type=int, default=2026, help="seed for the noisy channel")
    args = ap.parse_args()
    rng = random.Random(args.seed)

    #set-up: long-term signing keys and a shared session key
    clinic_key = ec.generate_private_key(ec.SECP256R1())
    hospital_key = ec.generate_private_key(ec.SECP256R1())
    clinic_pub, hospital_pub = clinic_key.public_key(), hospital_key.public_key()
    session_key = os.urandom(16)      # in practice agreed via ECDH/ECIES (Task 3)
    message = args.message.encode()

    banner("TEST 1: clinic -> hospital, clean channel")
    print("Plaintext      :", message.decode())
    tx, d = send(message, session_key, clinic_key, CLINIC_TO_HOSPITAL)
    print("IV (hex)       :", d["iv"].hex())
    print("Ciphertext     :", d["ciphertext"].hex()[:64] + "...", f"({len(d['ciphertext'])} bytes)")
    print("HMAC tag       :", d["tag"].hex())
    print("SHA-256 digest :", d["digest"].hex())
    print("Signature      :", d["signature"].hex()[:64] + "...", f"({len(d['signature'])} bytes)")
    print(f"Frame = {d['frame_len']} bytes; after Hamming(7,4) = {d['tx_bits']} bits "
          f"(x{d['tx_bits'] / (d['frame_len'] * 8):.2f} overhead, code rate 4/7)")
    attempt("T1", tx, session_key, clinic_pub, CLINIC_TO_HOSPITAL, message)

    banner("TEST 2: single-bit error on the channel (detected AND corrected)")
    bad_bit = 100
    rx = channel_flip_bits(tx, [bad_bit])
    print(f"Channel flips bit {bad_bit} of the transmitted stream "
          f"(codeword {bad_bit // 7}, position {bad_bit % 7 + 1}).")
    attempt("T2", rx, session_key, clinic_pub, CLINIC_TO_HOSPITAL, message)

    banner("TEST 3: random noise on a poor 3G link, bit error rate 0.2%")
    rx, flipped = channel_random_noise(tx, 0.002, rng)
    print(f"Channel flipped {len(flipped)} of {len(tx)} bits.")
    attempt("T3", rx, session_key, clinic_pub, CLINIC_TO_HOSPITAL, message)

    banner("TEST 4: two errors inside ONE codeword (beyond Hamming's power)")
    rx = channel_flip_bits(tx, [14 * 3, 14 * 3 + 1])      # bits 42 and 43: same codeword
    print("Hamming (7,4) cannot fix two errors in a codeword and mis-corrects it;")
    print("the HMAC then catches the damage, so the receiver rejects the message.")
    attempt("T4", rx, session_key, clinic_pub, CLINIC_TO_HOSPITAL, message)

    banner("TEST 5: heavy noise (bit error rate 5%) -> rejected, never accepted wrongly")
    rx, flipped = channel_random_noise(tx, 0.05, rng)
    print(f"Channel flipped {len(flipped)} of {len(tx)} bits.")
    attempt("T5", rx, session_key, clinic_pub, CLINIC_TO_HOSPITAL, message)

    banner("TEST 6: active attacker alters the ciphertext and re-encodes with Hamming")
    frame, _ = hamming_decode(tx)
    tampered = bytearray(frame)
    tampered[IV_LEN + 3] ^= 0x01                           # flip one ciphertext bit
    rx = hamming_encode(bytes(tampered))                   # parity looks perfectly valid
    print("Error-correcting codes give NO security: the parity is valid, but...")
    attempt("T6", rx, session_key, clinic_pub, CLINIC_TO_HOSPITAL, message)

    banner("TEST 7: impersonation - correct session key, but signed with a different key")
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    fake = b"Patient: PATIENT_TWELVE; Dx code: NORMAL; no treatment needed."
    tx_fake, _ = send(fake, session_key, attacker_key, CLINIC_TO_HOSPITAL)
    print("MAC alone cannot prove WHO sent it (both sides share the key); the signature can.")
    attempt("T7", tx_fake, session_key, clinic_pub, CLINIC_TO_HOSPITAL, fake)

    banner("TEST 8: hospital -> clinic, signed diagnosis report over a noisy link")
    report = (b"RADIOLOGY REPORT | Patient: PATIENT_TWELVE | MRI brain: no structural "
              b"abnormality. Findings consistent with malaria; start treatment per protocol.")
    tx_r, dr = send(report, session_key, hospital_key, HOSPITAL_TO_CLINIC)
    rx_r, flipped = channel_random_noise(tx_r, 0.002, rng)
    print(f"Channel flipped {len(flipped)} of {len(tx_r)} bits.")
    attempt("T8", rx_r, session_key, hospital_pub, HOSPITAL_TO_CLINIC, report)
    print("The clinic now holds a report that only the radiologist's private key could sign.")

    banner("TEST 9: larger binary payload (simulated 4 KB MRI slice) with noise")
    image = os.urandom(4096)
    tx_i, di = send(image, session_key, clinic_key, CLINIC_TO_HOSPITAL)
    rx_i, flipped = channel_random_noise(tx_i, 0.0005, rng)
    print(f"Frame {di['frame_len']} bytes -> {di['tx_bits']} bits; channel flipped {len(flipped)} bits.")
    attempt("T9", rx_i, session_key, clinic_pub, CLINIC_TO_HOSPITAL, image)


if __name__ == "__main__":
    main()
