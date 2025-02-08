import random
import hashlib  # For BLAKE2b hashing
from sympy import mod_inverse, randprime, primefactors
from colorama import Fore, Style
import math

##### KUZNYECHIK (GRASSHOPPER) ALGORITHM FUNCTIONS #####

# Kuznyechik key (256-bit) defined at the start
k = int('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef', 16)

# S-box for encryption
pi = [252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 
      233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 
      249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 
      5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 
      235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 
      181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 
      21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
      50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 
      223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 
      224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 
      167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 
      173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 
      7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 
      225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
      32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 
      89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182]

# Inverse S-box for decryption
pi_inv = [165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145, 
          100, 3, 87, 90, 28, 96, 7, 24, 33, 114, 168, 209, 41, 198, 164, 63, 
          224, 39, 141, 12, 130, 234, 174, 180, 154, 99, 73, 229, 66, 228, 21, 183, 
          200, 6, 112, 157, 65, 117, 25, 201, 170, 252, 77, 191, 42, 115, 132, 213, 
          195, 175, 43, 134, 167, 177, 178, 91, 70, 211, 159, 253, 212, 15, 156, 47, 
          155, 67, 239, 217, 121, 182, 83, 127, 193, 240, 35, 231, 37, 94, 181, 30, 
          162, 223, 166, 254, 172, 34, 249, 226, 74, 188, 53, 202, 238, 120, 5, 107, 
          81, 225, 89, 163, 242, 113, 86, 17, 106, 137, 148, 101, 140, 187, 119, 60, 
          123, 40, 171, 210, 49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46, 54, 
          219, 105, 179, 20, 149, 190, 98, 161, 59, 22, 102, 233, 92, 108, 109, 173, 
          55, 97, 75, 185, 227, 186, 241, 160, 133, 131, 218, 71, 197, 176, 51, 250,
          150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23, 27, 151, 125, 236, 88, 
          247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220, 232, 79, 29, 78, 4, 
          235, 248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19, 152, 2, 147, 128, 
          144, 208, 36, 52, 203, 237, 244, 206, 153, 16, 68, 64, 146, 58, 1, 38, 
          18, 26, 72, 104, 245, 129, 139, 199, 214, 32, 10, 8, 0, 76, 215, 116] 

def S(x):
    y = 0
    for i in reversed(range(16)):
        y <<= 8
        y ^= pi[(x >> (8 * i)) & 0xff]
    return y

def S_inv(x):
    y = 0
    for i in reversed(range(16)):
        y <<= 8
        y ^= pi_inv[(x >> (8 * i)) & 0xff]
    return y

def multiply_ints_as_polynomials(x, y):
    if x == 0 or y == 0:
        return 0
    z = 0
    while x:
        if x & 1:
            z ^= y
        y <<= 1
        x //= 2
    return z

def number_bits(x):
    nb = 0
    while x:
        nb += 1
        x //= 2
    return nb

def mod_int_as_polynomial(x, m):
    nbm = number_bits(m)
    while number_bits(x) >= nbm:
        x ^= m << (number_bits(x) - nbm)
    return x

def kuznyechik_multiplication(x, y):
    z = multiply_ints_as_polynomials(x, y)
    m = int('111000011', 2)
    return mod_int_as_polynomial(z, m)

def kuznyechik_linear_functional(x):
    C = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]
    y = 0
    while x:
        y ^= kuznyechik_multiplication(x & 0xff, C.pop())
        x //= 256
    return y

def R(x):
    a = kuznyechik_linear_functional(x)
    return (a << (8 * 15)) ^ (x >> 8)

def R_inv(x):
    a = x >> (15 * 8)
    x = (x << 8) & (2**128 - 1)
    b = kuznyechik_linear_functional(x ^ a)
    return x ^ b

def L(x):
    for _ in range(16):
        x = R(x)
    return x

def L_inv(x):
    for _ in range(16):
        x = R_inv(x)
    return x

def kuznyechik_key_schedule(k):
    keys = []
    a = k >> 128
    b = k & (2 ** 128 - 1)
    keys.append(a)
    keys.append(b)
    for i in range(4):
        for j in range(8):
            c = L(8 * i + j + 1)
            a, b = L(S(a ^ c)) ^ b, a
        keys.append(a)
        keys.append(b)
    return keys

# New functions that accept a precomputed key schedule:
def kuznyechik_encrypt_with_keys(x, keys):
    for round in range(9):
        x = L(S(x ^ keys[round]))
    return x ^ keys[-1]

def kuznyechik_decrypt_with_keys(x, keys):
    rev_keys = keys[::-1]
    for round in range(9):
        x = S_inv(L_inv(x ^ rev_keys[round]))
    return x ^ rev_keys[-1]

def string_to_hex(string):
    return string.encode('utf-8').hex()

def hex_to_string(hex_string):
    return bytes.fromhex(hex_string).decode('utf-8')

def split_into_16_char_blocks(text):
    return [text[i:i + 16] for i in range(0, len(text), 16)]

# Updated multi-block encryption function that computes the keys once.
def encrypt_process_more_than_16_char(string_blocks):
    CT_blocks = []
    keys = kuznyechik_key_schedule(k)
    print("ENCRYPTION KEY")
    for round in range(9):
        print(f"Key {round}: {keys[round]}")
    for block in string_blocks:
        PT = string_to_hex(block)
        PT_int = int(PT, 16)
        print(f"PT Block (Hex): {hex(PT_int)}")
        CT = kuznyechik_encrypt_with_keys(PT_int, keys)
        print(f"Hex CT (of PT Block): {hex(CT)}")
        CT_blocks.append(CT)
    return CT_blocks

# Updated multi-block decryption function that uses the precomputed keys.
def decrypt_process_more_than_16_char(ciphertext_blocks):
    DT_blocks = []
    keys = kuznyechik_key_schedule(k)
    keys_rev = keys[::-1]
    print("DECRYPTION KEY")
    for round in range(9):
        print(f"Key {round}: {keys_rev[round]}")
    for block in ciphertext_blocks:
        DT = kuznyechik_decrypt_with_keys(block, keys)
        DT_hex = hex(DT)[2:]
        if len(DT_hex) % 2:
            DT_hex = "0" + DT_hex
        DT_blocks.append(hex_to_string(DT_hex))
    return DT_blocks

# For short messages (one block), we still call the single-block functions.
def encrypt_process_less_than_16_char(string_block):
    PT = string_to_hex(string_block)
    PT_int = int(PT, 16)
    print(f"PT (Hex): {hex(PT_int)}")
    # Compute keys once for a single block.
    keys = kuznyechik_key_schedule(k)
    print("ENCRYPTION KEY")
    for round in range(9):
        print(f"Key {round}: {keys[round]}")
    CT = kuznyechik_encrypt_with_keys(PT_int, keys)
    print(f"Hex CT: {hex(CT)}")
    return CT

def decrypt_process_less_than_16_char(ciphertext):
    print(f"CT (Hex): {hex(ciphertext)}")
    keys = kuznyechik_key_schedule(k)
    keys_rev = keys[::-1]
    print("DECRYPTION KEY")
    for round in range(9):
        print(f"Key {round}: {keys_rev[round]}")
    DT = kuznyechik_decrypt_with_keys(ciphertext, keys)
    DT_hex = hex(DT)[2:]
    if len(DT_hex) % 2:
        DT_hex = "0" + DT_hex
    return hex_to_string(DT_hex)

##### ELGAMAL ALGORITHM FUNCTIONS #####

def smallest_primitive_root(p):
    phi = p - 1
    factors = primefactors(phi)
    for g in range(2, p):
        valid = True
        for q in factors:
            if pow(g, phi // q, p) == 1:
                valid = False
                break
        if valid:
            return g

def elgamal_generate_keys():
    p = randprime(int(math.pow(10, 20)), int(math.pow(10, 50)))
    print(f"Prime number p = {p}")
    g = smallest_primitive_root(p)
    print(f"Generator g = {g}")
    x = random.randint(1, p - 2)
    h = pow(g, x, p)
    return (p, g, h), x

def elgamal_encrypt(public_key, message):
    p, g, h = public_key
    encrypted_message = []
    for char in message:
        m = ord(char)
        if not (1 <= m <= p - 1):
            raise ValueError(f"Character {char} is out of valid range for encryption")
        k_rand = random.randint(1, p - 2)
        C1 = pow(g, k_rand, p)
        S_val = pow(h, k_rand, p)
        C2 = (m * S_val) % p
        encrypted_message.append((C1, C2))
    return encrypted_message

def elgamal_decrypt(private_key, public_key, encrypted_message):
    p, g, _ = public_key
    decrypted_chars = []
    for C1, C2 in encrypted_message:
        S_val = pow(C1, private_key, p)
        S_inv = pow(S_val, -1, p)
        m = (C2 * S_inv) % p
        decrypted_chars.append(chr(m))
    return ''.join(decrypted_chars)

#######################################
# Main function following the integrated workflow
#######################################
def main():
    # Step 1: Sender wishes to send a message.
    original_message = input("Enter the string to encrypt: ")
    print(f"\nOriginal Message (PT): {original_message}\n")
    print(f"Kuznyechik Key (Hex): {hex(k)}\n")
    
    # Step 2: Generate BLAKE2b hash of the plaintext.
    hash_obj = hashlib.blake2b(original_message.encode('utf-8'))
    hash_plaintext = hash_obj.hexdigest()
    print(f"BLAKE2b Hash of Plaintext: {hash_plaintext}\n")
    
    # Append the hash to the plaintext using a delimiter.
    combined_message = original_message + "||" + hash_plaintext
    print(f"Combined Message (Plaintext + Hash): {combined_message}\n")
    
    # Step 3: Encrypt the combined message using Kuznyechik.
    print("--- Encrypting Combined Message with Kuznyechik ---")
    blocks = split_into_16_char_blocks(combined_message)
    ciphertext_blocks = encrypt_process_more_than_16_char(blocks)
    print(f"\nCiphertext Blocks: {ciphertext_blocks}\n")
    
    # Step 4: Encrypt the hash with ElGamal.
    print("--- Encrypting Hash with ElGamal ---")
    public_key, private_key = elgamal_generate_keys()
    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")
    encrypted_hash = elgamal_encrypt(public_key, hash_plaintext)
    print(f"\nEncrypted Hash: {encrypted_hash}\n")
    
    # Simulate transmission...
    
    # Step 7: Recipient decrypts the encrypted hash using ElGamal.
    print("--- Decrypting Encrypted Hash with ElGamal ---")
    decrypted_hash = elgamal_decrypt(private_key, public_key, encrypted_hash)
    print(f"Decrypted Hash: {decrypted_hash}\n")
    
    # Step 6: Recipient decrypts the combined message using Kuznyechik.
    print("--- Decrypting Combined Message with Kuznyechik ---")
    decrypted_blocks = decrypt_process_more_than_16_char(ciphertext_blocks)
    combined_message_decrypted = "".join(decrypted_blocks)
    print(f"\nDecrypted Combined Message: {combined_message_decrypted}\n")
    
    # Parse out the original plaintext and the appended hash.
    try:
        decrypted_plaintext, appended_hash = combined_message_decrypted.split("||", 1)
    except ValueError:
        print("Error: The decrypted message does not contain the expected delimiter '||'.")
        return
    
    # Step 8: Verify the integrity of the message.
    print("--- Integrity Verification ---")
    recomputed_hash = hashlib.blake2b(decrypted_plaintext.encode('utf-8')).hexdigest()
    print(f"Recomputed Hash: {recomputed_hash}")
    if recomputed_hash == decrypted_hash:
        print(Fore.LIGHTGREEN_EX + "Integrity Verified: Hashes match!" + Style.RESET_ALL)
    else:
        print(Fore.RED + "Integrity Verification Failed: Hashes do not match!" + Style.RESET_ALL)
    
    # Step 9: Confirm the message's authenticity.
    print(f"\nFinal Decrypted Plaintext: {decrypted_plaintext}")
    if decrypted_plaintext == original_message:
        print(Fore.LIGHTGREEN_EX + "Decryption successful! Decrypted text matches original message." + Style.RESET_ALL)
    else:
        print(Fore.RED + "Decryption unsuccessful! Something went wrong!" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
