import struct
import hashlib

# BLAKE2b Constants - Initialization Vector (IV) from SHA-512
IV = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
]

# Permutation table for BLAKE2b rounds
SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]
]

# Rotation constants used in the G function
ROTATIONS = [32, 24, 16, 63]

def rotr(x, n):
    """Right rotate a 64-bit integer by n bits."""
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF

def G(v, a, b, c, d, x, y):
    """BLAKE2b's G function, mixing four words together."""
    v[a] = (v[a] + v[b] + x) & 0xFFFFFFFFFFFFFFFF
    v[d] = rotr(v[d] ^ v[a], ROTATIONS[0])
    v[c] = (v[c] + v[d]) & 0xFFFFFFFFFFFFFFFF
    v[b] = rotr(v[b] ^ v[c], ROTATIONS[1])
    v[a] = (v[a] + v[b] + y) & 0xFFFFFFFFFFFFFFFF
    v[d] = rotr(v[d] ^ v[a], ROTATIONS[2])
    v[c] = (v[c] + v[d]) & 0xFFFFFFFFFFFFFFFF
    v[b] = rotr(v[b] ^ v[c], ROTATIONS[3])

def F(h, m, t0, t1, f):
    """BLAKE2b compression function F."""
    v = [0] * 16
    v[0:8] = list(h)
    v[8:16] = list(IV)
    v[12] ^= t0  # Low word of the offset
    v[13] ^= t1  # High word of the offset
    v[14] ^= 0xFFFFFFFFFFFFFFFF if f else 0  # Finalization flag
    
    for i in range(12):  # Twelve rounds
        s = SIGMA[i % 10]
        G(v, 0, 4,  8, 12, m[s[0]], m[s[1]])
        G(v, 1, 5,  9, 13, m[s[2]], m[s[3]])
        G(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
        G(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
        G(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
        G(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
        G(v, 2, 7,  8, 13, m[s[12]], m[s[13]])
        G(v, 3, 4,  9, 14, m[s[14]], m[s[15]])
    
    for i in range(8):
        h[i] ^= v[i] ^ v[i + 8]

def blake2b(data, outlen=64, key=b''):
    """
    Compute BLAKE2b hash of input data.
    Default output length matches hashlib's default (64 bytes).
    """
    if not 1 <= outlen <= 64:
        raise ValueError("Output length must be between 1 and 64 bytes")
    if len(key) > 128:
        raise ValueError("Key length must not exceed 128 bytes")

    # Initialize state vector h with IV
    h = list(IV)  # Make a copy to avoid modifying the original

    # Initialize parameters block (little-endian)
    h[0] ^= 0x01010000 | (len(key) << 8) | outlen

    # Process key if present
    if key:
        key_block = key.ljust(128, b'\0')
        m = list(struct.unpack('<16Q', key_block))
        F(h, m, 128, 0, False)

    # Process message blocks
    data_len = len(data)
    
    if data_len == 0:
        # Empty message needs special handling
        F(h, [0] * 16, 0, 0, True)
        return b''.join(struct.pack('<Q', x) for x in h)[:outlen]
    
    # Process full blocks
    offset = 0
    while offset + 128 <= data_len:
        block = list(struct.unpack('<16Q', data[offset:offset + 128]))
        offset += 128
        F(h, block, offset, 0, offset == data_len)  # Final flag only if this is the last block
    
    # Process final partial block if it exists
    if offset < data_len:
        final_block = data[offset:].ljust(128, b'\0')
        block = list(struct.unpack('<16Q', final_block))
        F(h, block, data_len, 0, True)  # Always set final flag for partial block

    return b''.join(struct.pack('<Q', x) for x in h)[:outlen]

# Compare with hashlib implementation
def test_blake2b():
    """Test BLAKE2b implementation against Python's hashlib."""
    test_cases = [
        b"",  # Empty string
        b"Hello, BLAKE2b!",  # Regular string
        b"a" * 128,  # Exactly one block
        b"b" * 129,  # Just over one block
        b"test" * 32,  # Multiple blocks
    ]
    
    for test_data in test_cases:
        print(f"\nTesting with data length: {len(test_data)} bytes")
        my_hash = blake2b(test_data)
        ref_hash = hashlib.blake2b(test_data).digest()
        print("My BLAKE2b:", my_hash.hex())
        print("Ref BLAKE2b:", ref_hash.hex())
        assert my_hash == ref_hash, "Hashes do not match!"
    print("\nAll tests passed!")

test_blake2b()
