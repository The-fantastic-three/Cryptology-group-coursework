"""
Task 1(c) - Columnar transposition cipher with the keyword MEDIC.
Plaintext is written row-by-row under the keyword (padded with X), and the
columns are read off in alphabetical order of the keyword letters (C, D, E, I, M).
Expected ciphertext: EEAX TTEX ATVX IWMX PNLL
"""

plaintext = "PATIENTTWELVEMAL"
keyword = "MEDIC"
n = len(keyword)

# pad with X so the last row is full
padded = plaintext + "X" * (-len(plaintext) % n)
rows = [padded[i:i + n] for i in range(0, len(padded), n)]

order = sorted(range(n), key=lambda i: keyword[i])      # column read order
positions = {col: rank + 1 for rank, col in enumerate(order)}

print("Key word            :", "  ".join(keyword))
print("Column order        :", "  ".join(str(positions[i]) for i in range(n)))
for r in rows:
    print("                      " + "  ".join(r))

blocks = []
for col in order:
    column = "".join(row[col] for row in rows)
    blocks.append(column)
    print(f"Column {positions[col]} ({keyword[col]}): {column}")

ciphertext = " ".join(blocks)
print("\nEncrypted text =", ciphertext)
assert ciphertext == "EEAX TTEX ATVX IWMX PNLL"
