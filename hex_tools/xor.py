def xor_cipher(data: bytes, hex_key: str) -> bytes:
    key_int = int(hex_key, 16)
    return bytes([byte ^ key_int for byte in data])

# 1. Your input string (Hex values represented as text)
hex_input = "4C 4C 4C 15 4B 49 5A 58 4F 52 58 5A 57 56 5A 57 4C 5A 49 5E 5A 55 5A 57 42 48 52 48 15 58 54 56"

# 2. Convert that space-separated string into actual raw bytes
raw_bytes = bytes.fromhex(hex_input.replace(" ", ""))

my_key = "0x3B"

# 3. Perform the XOR
processed_bytes = xor_cipher(raw_bytes, my_key)

# 4. Print Results
print(f"Hex Output:   {processed_bytes.hex()}")

try:
    # This converts the resulting bytes into readable ASCII text
    ascii_text = processed_bytes.decode('ascii')
    print(f"ASCII Output: {ascii_text}")
except UnicodeDecodeError:
    print("ASCII Output: [Contains non-printable characters]")
