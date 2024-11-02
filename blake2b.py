'''
source: https://gist.github.com/sooryan/8d1b2c19bf0b971c11366b0680908d4b

+--------------+------------------+------------------+
|              | BLAKE2b          | BLAKE2s          |
+--------------+------------------+------------------+
| Bits in word | w  = 64          | w  = 32          |
| Rounds in F  | r  = 12          | r  = 10          |
| Block bytes  | bb = 128         | bb = 64          |
| Hash bytes   | 1 <= nn <= 64    | 1 <= nn <= 32    |
| Key bytes    | 0 <= kk <= 64    | 0 <= kk <= 32    |
| Input bytes  | 0 <= ll < 2**128 | 0 <= ll < 2**64  |
+--------------+------------------+------------------+
| G Rotation   | (R1, R2, R3, R4) | (R1, R2, R3, R4) |
|  constants   | (32, 24, 16, 63) | (16, 12,  8,  7) |
+--------------+------------------+------------------+

F, the compression function and G, the mixing function are described later

IV[0..7]    :: Initialization Vector (constant).

SIGMA[0..9] :: Message word permutations (constant).

p[0..7]     :: Parameter block (defines hash and key sizes).

m[0..15]    :: Sixteen words of a single message block.

h[0..7]     :: Internal state of the hash.

d[0..dd-1]  :: Padded input blocks. Each has "bb" bytes.

t           :: Message byte offset at the end of the current block.

f           :: Flag indicating the last block.  






'''


import hashlib

# Creating a BLAKE2b hash object
blake2b_hash = hashlib.blake2b()
blake2b_hash.update(b'Hello, world!')
print(blake2b_hash.hexdigest())


