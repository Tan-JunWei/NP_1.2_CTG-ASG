# CTG (Cryptography)

CTG is a module in Semester 1.2 of the Cybersecurity and Digital Forensics (CSF) course in Ngee Ann Polytechnic (NP). This module covers the essential concepts of Cryptography, including Public Key Infrastructure (PKI), 
Digital Signature and Certificate, and the various encryption/decryption algorithms.

This GitHub repository contains the Python script written for the module's assignment, where teams are expected to implement a simulated working prototype that would depict the operations and workings of the cryptographic algorithms.
This cryptosystem  aims to fufil the 5 goals of Cryptography, namely _`Confidentiality`, `Integrity`, `Availability`, `Authentication` and `Non-repudiation`_.

## Table of Contents

1. [Module Introduction](#ctg-cryptography)
2. [Cryptographic Goals](#overview-of-cryptographic-goals)
3. [Integration Workflow](#integration-workflow-steps)
4. [Getting Started](#getting-started)

## Overview of Cryptographic Goals

The five goals of cryptography are fundamental in ensuring secure communication and data management:

- Confidentiality: Ensuring that only authorized parties can access the information
- Integrity: Verifying that the information has not been altered during transmission
- Availability: Ensuring that authorized users have access to information when needed
- Authentication: Verifying the identity of the parties involved in communication
- Non-repudiation: Ensuring that a party cannot deny the authenticity of their signature on a document

# How the cryptosystem works

This cryptosystem includes the implementation of:

- **Symmetric Cryptosystem**: Kuznyechik ("Grasshopper") - Symmetric Block Cipher
  - [Code](./grasshopper_algorithm.py)

<div align="center">
  <img align="center" width="800" src="./assets/Kuznyechik Diagram.png" alt="Kuznyechik Diagram" />
  <h4>Diagram of Kuznyechik ("Grasshopper") - Symmetric Block Cipher</h4>
</div>

- **Asymmetric Cryptosystem**: ElGamal Encryption System
  - [Code](./ElGamal_algorithm.py)

<div align="center">
  <img align="center" width="800" src="./assets/ElGamal Diagram.png" alt="ElGamal Diagram" />
  <h4>Visual Representation of the ElGamal Encryption System</h4>
</div>

- **Cryptographic Hash Function**: BLAKE2b
  - [Code](./blake2b.py)

<div align="center">
  <img align="center" width="800" src="./assets/blake2b.png" alt="blake2b Diagram" />
  <h4>Visual Representation of the blake2b hash cipher</h4>
</div>

# Integration 

The integration of these 3 cryptographic components into a single, integrated cryptosystem ensures that all the goals of cryptography (`Confidentiality`,
`Integrity`, `Availability`, `Authentication`, `Non-repudiation`) can be achieved effectively.

## Integration Workflow (Steps)

### Step 1: Sender Wishes to Send a Message

- The sender wants to send a secure message to the recipient.
- The message is in plaintext format and needs to be encrypted to maintain confidentiality.

### Step 2: Generate Hash of the Message Using BLAKE2b

- To ensure `integrity` and `non-repudiation`, the sender generates a hash of the plaintext message.
  - The sender uses **BLAKE2b**, a cryptographic hash function, to create a unique, fixed-length hash of the plaintext data.
  - This hash acts as a digital fingerprint of the message.
  - The hash is then **appended** to the original plaintext message before encryption.

### Step 3: Encrypt the Message (PT + Hash) Using Kuznyechik (Symmetric Encryption)

- The sender uses the **Kuznyechik ("Grasshopper") cipher** to encrypt the message along with its hash.
  - This is a symmetric encryption algorithm, where the same key is used for both encryption and decryption.
  - The combined plaintext message and hash are converted into ciphertext using the symmetric Kuznyechik key.
  - The `confidentiality` of the message is ensured as only the authorized parties (who have access to the key) can decrypt it.

### Step 4: Encrypt the Hash with ElGamal (Asymmetric Encryption)

- The sender then uses the **ElGamal encryption system** to encrypt the original hash separately.
  - This uses **asymmetric encryption**, where a pair of keys (public and private) is used.
  - The sender encrypts the original hash using the **recipient’s public key**.
  - This ensures `authentication` and `non-repudiation`, as only the recipient can decrypt the hash using their private key, verifying the integrity and authenticity of the sender's message.

### Step 5: Send the Encrypted Message and the Sender’s Public Key to the Recipient

- The sender sends the following to the recipient:
  - **Encrypted message (ciphertext) with the appended plaintext hash (encrypted using ElGamal)**.
  - **Sender’s public key**: Used by the recipient to verify the authenticity of the sender and the message.

### Step 6: Recipient Decrypts the Encrypted Message Using Kuznyechik

- The recipient uses their **private key** to decrypt the message that was encrypted using Kuznyechik.
  - This will give them the original plaintext message along with the appended hash.
  - `Confidentiality` is maintained as only the intended recipient, who has the correct private key, can decrypt the message.

### Step 7: Recipient Decrypts the Appended Encrypted Hash Using Their Private Key (ElGamal)

- The recipient then decrypts the encrypted hash (which was appended to the message) using their **private key** (ElGamal decryption).
  - This process will give them the original hash value that was generated by the sender.

### Step 8: Verify the Integrity of the Message

- The recipient re-generates the hash of the decrypted plaintext message using `BLAKE2b`.
  - If the newly generated hash matches the decrypted hash from Step 7, it proves that the message has not been altered and is intact.
  - If the hashes match, the `integrity` and `non-repudiation` of the message are verified.

### Step 9: Recipient Confirms the Message’s Authenticity

- The recipient can now be confident that:
  - The message has not been tampered with (ensuring `integrity`).
  - The message was indeed sent by the rightful sender (ensuring `authentication`).
  - The sender cannot deny sending the message (ensuring `non-repudiation`).

This step-by-step integration ensures that all cryptographic goals are achieved effectively: **Confidentiality**, **Integrity**, **Availability**, **Authentication**, and **Non-repudiation**.

---

# Getting Started

1. Clone the Git repository:

```bash
git clone https://github.com/Tan-JunWei/NP_1.2_CTG-ASG.git
```

2. Navigate to folder:

```bash
cd NP_1.2_CTG-ASG
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the integrated script (WIP):

```bash
python integrate_with_hash.py
```

