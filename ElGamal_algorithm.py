'''
ElGamal Encrption Algorithm

Source(s): 
https://www.geeksforgeeks.org/elgamal-encryption-algorithm
https://www.sciencedirect.com/topics/computer-science/discrete-logarithm
https://medium.com/@MatinGhanbari/the-elgamal-encryption-algorithm-dc1dc4442281#:~:text=The%20ElGamal%20encryption%20algorithm%20is%20a%20public%20key%20encryption%20scheme,%E2%89%A4%20x%20%E2%89%A4%20p%20%E2%88%92%202.

1. Key Generation 🔑

## Public Parameters: 
- Select a large prime number p (p should be large enough to make it difficult to solve the discrete logarithm problem)
- Select a generator g of the multiplicative group of integers modulo p (Z*p).

A generator g is an element of the multiplicative group Z*p, such that when it is raised to various powers like g^1,g^2,.. can produce 
every element in Z*p. Choosing a generator leverages the cyclic group structure of Z*p for secure cryptographic operations.

The values p and g are public parameters, and can be shared openly. 

➕➖✖️➗🟰 Discrete logarithm - What is it? 
A logarithm is the opposite of exponentiation. For example, in the equation 2^3 = 8, the base is 2, the exponent is 3, and the result is
8. 
The logarithm of 8 with base 2 is 3. The discrete logarithm problem is the problem of finding the exponent when the base and the result 
are known.

Application of the discrete logarithm problem:
Given a prime number p, a generator g of the multiplicative group of integers modulo p, and an element h of the group, find an integer k
such that g^k mod p = h.

This problem is difficult to solve when p is large enough. The security of the ElGamal encryption algorithm is based on the difficulty of solving
the discrete logarithm problem (computationally hard).


🔏 Private Key:
- Select a random integer x such that 1 ≤ x ≤ (p-2)
The private key is x.

📢 Public Key:
- Compute h = g^x mod p. 
The public key is (p, g, h).



2. Encryption

Message: m (must be an integer such that 1 ≤ m ≤ p-1 to be compatible with the modular arithmetic operations in the algorithm)
- Select a random integer k such that 1 ≤ k ≤ p-2. 
- Compute C1 = g^k mod p.
- Compute S = h^k mod p.
- Compute C2 = m * S mod p. 
The ciphertext will be (C1, C2).

During the encryption process, the sender uses the public key (p,g,h) to encrypt the message m. The sender also takes the original message m and 
multiplies it with a value known as a shared secret S, to calculate C2. 

Both C1 and C2 are then sent to the receiver.

3. Decryption

Given the ciphertext (C1, C2) and the private key x, the decryption process is as follows:

The receiver first computers the shared secret S = C1^x mod p.

While the formulas to obtain S are different in the encryption and decryption processes, the value of shared secret S calculated should be
the same in both cases.

The receiver then computes the original message m = C2 * S^-1 mod p, where S^-1 is the modular inverse of S.
'''

import random
from sympy import mod_inverse

# Key Generation
def generate_keys():
    # Public parameters
    # p = 23  # Large prime number, for simplicity, we're using a small prime here
    # g = 5   # Generator, must be primitive root modulo p

    # TODO: Choose a random large prime number and a generator
    p = 29
    g = 2

    # Private key
    # x = random.randint(1, p - 2)
    x = 5

    # Public key
    h = pow(g, x, p)

    return (p, g, h), x

# Encryption
def encrypt(public_key, message):
    p, g, h = public_key

    # Ensure message is in the valid range
    if not (1 <= message <= p - 1):
        raise ValueError("Message must be in the range 1 <= m <= p-1")

    # Random integer k
    # k = random.randint(1, p - 2)
    k = 4

    # Compute C1 and C2
    C1 = pow(g, k, p)
    S = pow(h, k, p)
    C2 = (message * S) % p

    print(f"C1 = {C1}, C2 = {C2}, S = {S}")

    return (C1, C2)

# Decryption
def decrypt(private_key, public_key, ciphertext):
    p, g, h = public_key
    C1, C2 = ciphertext
    x = private_key

    # Compute shared secret S
    S = pow(C1, x, p)
    print(f"Shared Secret S = {S}")

    # Compute modular inverse of S
    S_inv = mod_inverse(S, p)
    print(f"Modular Inverse of S = {S_inv}")

    # Recover the message
    message = (C2 * S_inv) % p
    print(f"Recovered Message = {message}")
    return message

# Example usage
if __name__ == "__main__":
    # Key generation
    public_key, private_key = generate_keys()
    print("Public Key:", public_key)
    print("Private Key:", private_key)

    # Message to encrypt
    message = 6  # Example message
    print("Original Message:", message)

    # Encrypt
    ciphertext = encrypt(public_key, message)
    print("Ciphertext:", ciphertext)

    # Decrypt
    decrypted_message = decrypt(private_key, public_key, ciphertext)
    print("Decrypted Message:", decrypted_message)
