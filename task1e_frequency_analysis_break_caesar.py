"""
Task 1(e) - Stretch task: frequency analysis in Python used to break a
substitution cipher (here a Caesar shift) of our own design.
The most frequent ciphertext letter is assumed to be 'E' (most common letter
in English), which gives the guessed key.
"""
from collections import Counter


def frequency_analysis(ciphertext):
    cleaned_text = [char.upper() for char in ciphertext if char.isalpha()]
    total_chars = len(cleaned_text)

    counts = Counter(cleaned_text)

    print("Letter Frequencies: ")
    for letter, count in counts.most_common():
        percentage = (count / total_chars) * 100
        print(f"{letter}: {count} ({percentage:.2f}%)")


def break_caesar_cipher(ciphertext):
    counts = Counter([c for c in ciphertext if c.isalpha()])
    most_common_char = counts.most_common(1)[0][0]

    guessed_key = (ord(most_common_char) - ord('E')) % 26

    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            new_pos = (ord(char.upper()) - ord('A') - guessed_key) % 26
            plaintext += chr(new_pos + ord('A'))

    print(f"Guessed Key: {guessed_key}")
    print(f"Decrypted plaintext: {plaintext}")


if __name__ == "__main__":
    ciphertext = ("SDWLHQWWZHOYHLVDWZHQWBBHDUROGPDOHIURPDUXUDOFOXVWHULQXJDQGDSUHVHQWLQJ"
                  "ZLWKDKLJKIHYHUVHYHUHKHDGDFKH")
    frequency_analysis(ciphertext)
    break_caesar_cipher(ciphertext)
