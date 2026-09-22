import random
import string


# ==========================================
# Configuration
# ==========================================

SALT_COUNT = 10
MAX_SHIFT = 9

# Each salt metadata entry:
#
# position = 3 digits
# length   = 2 digits
#
# Example:
# position 5, length 1
# -> 00501

METADATA_ENTRY_LENGTH = 5
MAX_CIPHERTEXT_LENGTH = 1000


# ==========================================
# Caesar Encode
# ==========================================

def caesar_encode(text):

    result = []
    key = []

    for char in text:

        if "a" <= char <= "z":

            shift = random.randint(
                0,
                MAX_SHIFT
            )

            encoded = chr(
                (
                    ord(char)
                    - ord("a")
                    + shift
                ) % 26
                + ord("a")
            )

            result.append(encoded)
            key.append(str(shift))

        elif "A" <= char <= "Z":

            shift = random.randint(
                0,
                MAX_SHIFT
            )

            encoded = chr(
                (
                    ord(char)
                    - ord("A")
                    + shift
                ) % 26
                + ord("A")
            )

            result.append(encoded)
            key.append(str(shift))

        else:

            # Spaces, punctuation, numbers,
            # Unicode, etc. stay unchanged.
            result.append(char)
            key.append("0")

    return "".join(result), "".join(key)


# ==========================================
# Caesar Decode
# ==========================================

def caesar_decode(text, key):

    if len(text) != len(key):

        raise ValueError(
            "Caesar key length does not match text length."
        )

    result = []

    for char, shift_char in zip(
        text,
        key
    ):

        if not shift_char.isdigit():

            raise ValueError(
                "Caesar key contains invalid characters."
            )

        shift = int(shift_char)

        if "a" <= char <= "z":

            decoded = chr(
                (
                    ord(char)
                    - ord("a")
                    - shift
                ) % 26
                + ord("a")
            )

            result.append(decoded)

        elif "A" <= char <= "Z":

            decoded = chr(
                (
                    ord(char)
                    - ord("A")
                    - shift
                ) % 26
                + ord("A")
            )

            result.append(decoded)

        else:

            result.append(char)

    return "".join(result)


# ==========================================
# Encode
# ==========================================

def encode(text):

    # --------------------------------------
    # Step 1:
    # Caesar encode the original text
    # --------------------------------------

    caesar_text, caesar_key = caesar_encode(
        text
    )

    # --------------------------------------
    # Step 2:
    # Generate random salt characters
    # --------------------------------------

    salts = []

    for _ in range(SALT_COUNT):

        salts.append(
            random.choice(
                string.ascii_lowercase
            )
        )

    # --------------------------------------
    # Step 3:
    # Randomly decide which salts are used
    # --------------------------------------

    selected_salts = []

    for salt in salts:

        if random.randint(0, 1) == 1:

            selected_salts.append(salt)

    salt_count = len(selected_salts)

    # --------------------------------------
    # Step 4:
    # Calculate final ciphertext length
    # --------------------------------------

    final_length = (
        len(caesar_text)
        + salt_count
    )

    if final_length > MAX_CIPHERTEXT_LENGTH:

        raise ValueError(
            "Text is too long. "
            "Maximum ciphertext length is 1000 characters."
        )

    # --------------------------------------
    # Step 5:
    # Choose UNIQUE final positions
    #
    # These are positions in the FINAL
    # ciphertext.
    #
    # Therefore they never shift later.
    # --------------------------------------

    if salt_count > 0:

        positions = random.sample(
            range(final_length),
            salt_count
        )

        positions.sort()

    else:

        positions = []

    # --------------------------------------
    # Step 6:
    # Build ciphertext directly
    # --------------------------------------

    ciphertext_list = []

    salt_metadata = []

    original_index = 0
    salt_index = 0

    position_set = set(
        positions
    )

    for position in range(final_length):

        if position in position_set:

            salt_char = selected_salts[
                salt_index
            ]

            ciphertext_list.append(
                salt_char
            )

            salt_metadata.append(
                (
                    position,
                    1
                )
            )

            salt_index += 1

        else:

            ciphertext_list.append(
                caesar_text[
                    original_index
                ]
            )

            original_index += 1

    ciphertext = "".join(
        ciphertext_list
    )

    # --------------------------------------
    # Step 7:
    # Build metadata
    # --------------------------------------

    metadata = ""

    for position, length in salt_metadata:

        metadata += (
            f"{position:03d}"
            f"{length:02d}"
        )

    metadata_length = len(
        metadata
    )

    # --------------------------------------
    # Step 8:
    # Build final key
    #
    # [Caesar key]
    # [salt metadata]
    # [metadata length]
    # --------------------------------------

    key = (
        caesar_key
        + metadata
        + str(metadata_length)
    )

    # --------------------------------------
    # Step 9:
    # SELF TEST
    #
    # This is extremely important.
    #
    # If our own decoder cannot recover
    # the original text, do NOT return a
    # broken ciphertext/key.
    # --------------------------------------

    test_result = decode(
        ciphertext,
        key
    )

    if test_result != text:

        raise RuntimeError(
            "INTERNAL ERROR: "
            "Encode/Decode self-test failed."
        )

    return ciphertext, key


# ==========================================
# Decode
# ==========================================

def decode(ciphertext, key):

    # --------------------------------------
    # Basic validation
    # --------------------------------------

    if not isinstance(
        ciphertext,
        str
    ):

        raise TypeError(
            "Ciphertext must be a string."
        )

    if not isinstance(
        key,
        str
    ):

        raise TypeError(
            "Key must be a string."
        )

    if len(key) == 0:

        raise ValueError(
            "Key cannot be empty."
        )

    if len(ciphertext) > MAX_CIPHERTEXT_LENGTH:

        raise ValueError(
            "Ciphertext is too long."
        )

    # --------------------------------------
    # The LAST digits of the key contain
    # metadata length.
    #
    # Metadata length is always:
    #
    # salt_count * 5
    #
    # Therefore it can be determined by
    # checking the possible digit lengths.
    # --------------------------------------

    metadata_length = None
    metadata_digits = None

    for digits in (1, 2, 3, 4, 5, 6):

        if len(key) < digits:

            continue

        candidate = key[-digits:]

        if not candidate.isdigit():

            continue

        candidate_length = int(
            candidate
        )

        # Metadata must be divisible by 5.
        if candidate_length % METADATA_ENTRY_LENGTH != 0:

            continue

        # Metadata cannot exceed the key.
        if candidate_length + digits > len(key):

            continue

        # Metadata must contain complete entries.
        if candidate_length < 0:

            continue

        # Check that this candidate produces
        # a valid Caesar key length.
        salt_count = (
            candidate_length
            // METADATA_ENTRY_LENGTH
        )

        caesar_key_length = (
            len(ciphertext)
            - salt_count
        )

        if caesar_key_length < 0:

            continue

        expected_key_length = (
            caesar_key_length
            + candidate_length
            + digits
        )

        if expected_key_length == len(key):

            # Make sure this candidate is
            # unambiguous.
            if metadata_length is not None:

                raise ValueError(
                    "Invalid key: ambiguous metadata length."
                )

            metadata_length = (
                candidate_length
            )

            metadata_digits = digits

    # --------------------------------------
    # Validate metadata length
    # --------------------------------------

    if metadata_length is None:

        raise ValueError(
            "Invalid key structure."
        )

    # --------------------------------------
    # Calculate lengths
    # --------------------------------------

    salt_count = (
        metadata_length
        // METADATA_ENTRY_LENGTH
    )

    caesar_key_length = (
        len(ciphertext)
        - salt_count
    )

    # --------------------------------------
    # Extract metadata length
    # --------------------------------------

    stored_metadata_length = int(
        key[
            len(key)
            - metadata_digits:
        ]
    )

    if stored_metadata_length != metadata_length:

        raise ValueError(
            "Invalid metadata length."
        )

    # --------------------------------------
    # Extract Caesar key
    # --------------------------------------

    caesar_key = key[
        :caesar_key_length
    ]

    # --------------------------------------
    # Extract metadata
    # --------------------------------------

    metadata_start = (
        caesar_key_length
    )

    metadata_end = (
        metadata_start
        + metadata_length
    )

    metadata = key[
        metadata_start:
        metadata_end
    ]

    # --------------------------------------
    # Validate Caesar key
    # --------------------------------------

    if len(caesar_key) != caesar_key_length:

        raise ValueError(
            "Invalid Caesar key length."
        )

    if not caesar_key.isdigit():

        raise ValueError(
            "Invalid Caesar key."
        )

    # --------------------------------------
    # Parse salt metadata
    # --------------------------------------

    salt_positions = []

    for i in range(
        0,
        len(metadata),
        METADATA_ENTRY_LENGTH
    ):

        position_text = metadata[
            i:i + 3
        ]

        length_text = metadata[
            i + 3:i + 5
        ]

        if not position_text.isdigit():

            raise ValueError(
                "Invalid salt position."
            )

        if not length_text.isdigit():

            raise ValueError(
                "Invalid salt length."
            )

        position = int(
            position_text
        )

        length = int(
            length_text
        )

        if length <= 0:

            raise ValueError(
                "Invalid salt length."
            )

        if position < 0:

            raise ValueError(
                "Invalid salt position."
            )

        if (
            position + length
            > len(ciphertext)
        ):

            raise ValueError(
                "Invalid salt position."
            )

        salt_positions.append(
            (
                position,
                length
            )
        )

    # --------------------------------------
    # Validate salt count
    # --------------------------------------

    if len(salt_positions) != salt_count:

        raise ValueError(
            "Salt metadata count mismatch."
        )

    # --------------------------------------
    # Validate that salt ranges don't overlap
    # --------------------------------------

    sorted_positions = sorted(
        salt_positions,
        key=lambda item: item[0]
    )

    previous_end = 0

    for position, length in sorted_positions:

        if position < previous_end:

            raise ValueError(
                "Overlapping salt metadata."
            )

        previous_end = (
            position
            + length
        )

    # --------------------------------------
    # Remove salts
    #
    # RIGHT -> LEFT
    #
    # This prevents deleting one salt from
    # changing the position of another salt
    # that we still need to remove.
    # --------------------------------------

    result = list(
        ciphertext
    )

    for position, length in sorted(
        salt_positions,
        reverse=True
    ):

        del result[
            position:
            position + length
        ]

    caesar_text = "".join(
        result
    )

    # --------------------------------------
    # Verify Caesar text length
    # --------------------------------------

    if len(caesar_text) != len(caesar_key):

        raise ValueError(
            "Key length does not match ciphertext."
        )

    # --------------------------------------
    # Caesar Decode
    # --------------------------------------

    return caesar_decode(
        caesar_text,
        caesar_key
    )


# ==========================================
# Main CLI
# ==========================================

print(
    "=== Caesar + Salt Cipher CLI Tool ==="
)


while True:

    print(
        "\n----------------------------------"
    )

    mode = (
        input(
            "Select mode "
            "(1: Encode / 2: Decode / q: Quit): "
        )
        .strip()
        .lower()
    )

    # ======================================
    # Encode
    # ======================================

    if mode == "1":

        text = input(
            "Enter text to encode: "
        )

        try:

            ciphertext, key = encode(
                text
            )

            print("\n[Result]")

            print(
                "Ciphertext :",
                ciphertext
            )

            print(
                "Key        :",
                key
            )

        except Exception as error:

            print(
                "\n[Error]",
                error
            )

    # ======================================
    # Decode
    # ======================================

    elif mode == "2":

        # IMPORTANT:
        #
        # Do NOT strip ciphertext.
        # Spaces are valid data.
        ciphertext = input(
            "Enter ciphertext : "
        )

        # Key contains no meaningful
        # whitespace, so stripping it is safe.
        key = input(
            "Enter key        : "
        ).strip()

        try:

            original = decode(
                ciphertext,
                key
            )

            print("\n[Result]")

            print(
                "Decoded text:",
                original
            )

        except Exception as error:

            print(
                "\n[Error]",
                error
            )

    # ======================================
    # Quit
    # ======================================

    elif mode in (
        "q",
        "quit"
    ):

        break

    else:

        print(
            "Invalid option! "
            "Please enter 1, 2, or 'q' to quit."
        )
