'''
ElGamal Encrption Algorithm

Source(s): 
https://www.geeksforgeeks.org/elgamal-encryption-algorithm
https://www.sciencedirect.com/topics/computer-science/discrete-logarithm
https://medium.com/@MatinGhanbari/the-elgamal-encryption-algorithm-dc1dc4442281#:~:text=The%20ElGamal%20encryption%20algorithm%20is%20a%20public%20key%20encryption%20scheme,%E2%89%A4%20x%20%E2%89%A4%20p%20%E2%88%92%202.

1. Key Generation

## Public Parameters: 
- Select a large prime number p (p should be large enough to make it difficult to solve the discrete logarithm problem)
- Select a generator g of the multiplicative group of integers modulo p (Z*p).

A generator g is an element of the multiplicative group Z*p, such that when it is raised to various powers like g^1,g^2,.. can produce 
every element in Z*p. Choosing a generator leverages the cyclic group structure of Z*p for secure cryptographic operations.

The values p and g are public parameters, and can be shared openly. 

## Discrete logarithm - What is it?
A logarithm is the opposite of exponentiation. For example, in the equation 2^3 = 8, the base is 2, the exponent is 3, and the result is
8. 
The logarithm of 8 with base 2 is 3. The discrete logarithm problem is the problem of finding the exponent when the base and the result 
are known.

Application of the discrete logarithm problem:
Given a prime number p, a generator g of the multiplicative group of integers modulo p, and an element h of the group, find an integer k
such that g^k mod p = h.

This problem is difficult to solve when p is large enough. The security of the ElGamal encryption algorithm is based on the difficulty of solving
the discrete logarithm problem (computationally hard).


## Private Key:
- Select a random integer x such that 1 ≤ x ≤ (p-2)
The private key is x.

## Public Key:
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

# Python program to illustrate ElGamal encryption
import random 
from math import pow

a = random.randint(2, 10)

def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b;
    else:
        return gcd(b, a % b)

# Generating large random numbers
def gen_key(q):
    key = random.randint(pow(10, 20), q)
    while gcd(q, key) != 1:
        key = random.randint(pow(10, 20), q)

    return key

# Modular exponentiation
def power(a, b, c):
    x = 1
    y = a

    while b > 0:
        if b % 2 != 0:
            x = (x * y) % c;
        y = (y * y) % c
        b = int(b / 2)

    return x % c

# Asymmetric encryption
def encrypt(msg, q, h, g):
    en_msg = []

    k = gen_key(q)# Private key for sender
    s = power(h, k, q)
    p = power(g, k, q)
    
    for i in range(0, len(msg)):
        en_msg.append(msg[i])

    print("g^k used : ", p)
    print("g^ak used : ", s)
    for i in range(0, len(en_msg)):
        en_msg[i] = s * ord(en_msg[i])

    return en_msg, p

def decrypt(en_msg, p, key, q):
    dr_msg = []
    h = power(p, key, q)
    for i in range(0, len(en_msg)):
        dr_msg.append(chr(int(en_msg[i]/h)))
        
    return dr_msg

# Driver code
def main():
    msg = 'encryption'
    print("Original Message :", msg)

    q = random.randint(pow(10, 20), pow(10, 50))
    g = random.randint(2, q)

    key = gen_key(q)# Private key for receiver
    h = power(g, key, q)
    print("g used : ", g)
    print("g^a used : ", h)

    en_msg, p = encrypt(msg, q, h, g)
    dr_msg = decrypt(en_msg, p, key, q)
    dmsg = ''.join(dr_msg)
    print("Decrypted Message :", dmsg);

if __name__ == '__main__':
    main()