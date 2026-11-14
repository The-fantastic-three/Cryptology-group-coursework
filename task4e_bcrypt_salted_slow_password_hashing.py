"""
Task 4(e) - Password hashing with a per-user salt and a slow hash (bcrypt).
Same password -> different hashes (random salt), so precomputed rainbow tables
are useless; cost factor 12 makes each guess expensive for an attacker.
"""
import bcrypt

password = b"Nurse@2026"

hash_a = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
hash_b = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))

print("(e) Hash 1:", hash_a.decode())
print("Hash 2:", hash_b.decode())
print("Same password, different hashes:", hash_a != hash_b)
print("checkpw(correct):", bcrypt.checkpw(password, hash_a),
      "| checkpw(wrong):", bcrypt.checkpw(b"nurse@2026", hash_a))
