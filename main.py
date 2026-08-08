import random


def encode(text):
    result = ""
    key = ""
    for _ in text:
        if _.islower():
            seed = random.randint(0, 9)
            result += chr((ord(_) - 97 + seed) % 26 + 97)
            key += str(seed)
        elif _.isupper():
            seed = random.randint(0, 9)
            result += chr((ord(_) - 65 + seed) % 26 + 65)
            key += str(seed)
        else:
            result += _
            key += "0"
    return result, key


def decode(text, key):
    result = ""
    for char, shift in zip(text, key):
        seed = int(shift)
        if char.islower():
            result += chr((ord(char) - 97 - seed) % 26 + 97)
        elif char.isupper():
            result += chr((ord(char) - 65 - seed) % 26 + 65)
        else:
            result += char
    return result


# --- Main Script ---
print("=== Caesar Cipher CLI Tool ===")

while True:
    print("\n----------------------------------")
    mode = (
        input("Select mode (1: Encode / 2: Decode / q: Quit): ")
        .strip()
        .lower()
    )

    if mode == "1":
        text = input("| Only text will be encoded | Enter text to encode: ")
        cipher, key = encode(text)
        print("\n[Result]")
        print("Ciphertext :", cipher)
        print("Key        :", key)

    elif mode == "2":
        cipher = input("Enter ciphertext : ")
        key = input("Enter key        : ")
        if len(cipher) != len(key):
            print("\n[Error] Key length does not match ciphertext length!")
        else:
            original = decode(cipher, key)
            print("\n[Result]")
            print("Decoded text:", original)

    elif mode == "q" or mode == "quit":
        break

    else:
        print("Invalid option! Please enter 1, 2, or 'q' to quit.")
