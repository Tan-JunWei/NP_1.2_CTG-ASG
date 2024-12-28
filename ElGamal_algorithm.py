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
from sympy import mod_inverse, randprime, primefactors
import math

def smallest_primitive_root(p):
    """
    Finds the smallest primitive root for a large prime p.
    
    Args:
        p (int): A large prime number.
        
    Returns:
        int: The smallest primitive root g for the prime p.
    """
    
    # Compute phi(p), which for a prime p is p-1
    phi = p - 1
    
    # Get the prime factors of phi(p)
    factors = primefactors(phi)
    
    # Test potential generators in increasing order
    for g in range(2, p):  # Start testing from 2 upwards
        valid = True
        
        # Check g^((p-1)/q) mod p != 1 for all prime factors q of phi(p)
        for q in factors:
            if pow(g, phi // q, p) == 1:
                valid = False
                break
        
        if valid:
            return g


# Key Generation
def generate_keys(): 
    # Public parameters
    p = randprime(math.pow(10,20), math.pow(10,50)) # Generate large prime number
    print(f"Prime number p = {p}")

    # Compute Generator (primitive root modulo p). smallest primitive root is used for simplicity
    g = smallest_primitive_root(p) 
    print(f"Generator g = {g}")

    # Private key
    x = random.randint(1, p - 2)

    # Public key
    h = pow(g, x, p)

    return (p, g, h), x

def encrypt(public_key, message):
    p, g, h = public_key
    encrypted_message = []

    for char in message:
        # Convert character to ASCII value
        m = ord(char)
        
        # Ensure m is within the valid range (1 ≤ m ≤ p-1)
        if not (1 <= m <= p - 1):
            raise ValueError(f"Character {char} is out of the valid range for encryption")

        # Random integer k where 1 ≤ k ≤ p-2
        k = random.randint(1, p - 2)

        C1 = pow(g, k, p)            # C1 = g^k mod p
        S = pow(h, k, p)             # Shared secret S = h^k mod p
        C2 = (m * S) % p             # C2 = (m * S) mod p

        encrypted_message.append((C1, C2))

    return encrypted_message # list of ciphertext pairs

def decrypt(private_key, public_key, encrypted_message):
    p, g, _ = public_key
    key = private_key
    decrypted_message = []

    for C1, C2 in encrypted_message:
        # Receiver computes the shared secret S = C1^key mod p
        S = pow(C1, key, p)
        
        # Compute the original ASCII value m = (C2 * S^-1) mod p
        S_inv = pow(S, -1, p)
        m = (C2 * S_inv) % p
        
        # Convert numeric ASCII value back to character
        decrypted_message.append(chr(m))

    return ''.join(decrypted_message)

if __name__ == "__main__":
    # Key generation
    print("--- Key Generation ---\n")
    public_key, private_key = generate_keys()
    print("Public Key:", public_key)
    print("Private Key:", private_key)

    # Message to encrypt
    print("\n--- Encryption ---\n")

    message = "Hello"
    print("Original Message:", message)

    # Encrypt
    ciphertext = encrypt(public_key, message)
    print("Ciphertext:", ciphertext)

    # Decrypt
    print("\n--- Decryption ---\n")
    decrypted_message = decrypt(private_key, public_key, ciphertext)
    print("Decrypted Message:", decrypted_message)
