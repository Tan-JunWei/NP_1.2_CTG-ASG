# CTG (Cryptography)

CTG is a module in Semester 1.2 of the Cybersecurity and Digital Forensics (CSF) course in Ngee Ann Polytechnic (NP). This module covers the essential concepts of Cryptography, including Public Key Infrastructure (PKI), 
Digital Signature and Certificate, and the various encryption/decryption algorithms.

This GitHub repository contains the Python script written for the module's assignment, where teams are expected to implement a simulated working prototype that would depict the operations and workings of the cryptographic algorithms.
This cryptosystem  aims to fufil the 5 goals of Cryptography, namely _Confidentiality, Integrity, Availability, Authentication and Non-repudiation_.

## Overview of Cryptographic Goals
- Confidentiality: Ensuring that only authorized parties can access the information
- Integrity: Verifying that the information has not been altered during transmission
- Availability: Ensuring that authorized users have access to information when needed
- Authentication: Verifying the identity of the parties involved in communication
- Non-repudiation: Ensuring that a party cannot deny the authenticity of their signature on a document

# How the cryptosystem works

This cryptosystem includes the implementation of:

- **Symmetric Cryptosystem**: Kuznyechik ("Grasshopper") - Symmetric Block Cipher

<div align="center">
  <img align="center" width="800" src="./assets/Kuznyechik Diagram.png" alt="Kuznyechik Diagram" />
  <h4>Diagram of Kuznyechik ("Grasshopper") - Symmetric Block Cipher</h4>
</div>

- **Asymmetric Cryptosystem**: ElGamal Encryption System

<div align="center">
  <img align="center" width="800" src="./assets/ElGamal Diagram.png" alt="ElGamal Diagram" />
  <h4>Visual Representation of the ElGamal Encryption System</h4>
</div>

- **Cryptographic Hash Function**: BLAKE2b

# Integration 

The integration of these 3 cryptographic components into a single, integrated cryptosystem ensures that all the goals of cryptography (`Confidentiality`,
`Integrity`, `Availability`, `Authentication`, `Non-repudiation`) can be achieved effectively.

<div align="center">
  <img align="center" width="800" src="./assets/integration.png" alt="Diagram of cryptosystem with the integration of all 3 algorithms" />
  <h4>Diagram of Integrated Cryptosystem</h4>
</div>

## Integration workflow (steps)

1. 
2. 
3. 
4. 

# Getting Started

1. Clone the Git repository:

```bash
git clone https://github.com/Tan-JunWei/NP_1.2_CTG-ASG-Python-script.git
```

2. Navigate to folder:

```bash
cd NP_1.2_CTG-ASG-Python-script
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the integrated script (WIP):

```bash
python < INTEGRATED-script-name >.py
```

