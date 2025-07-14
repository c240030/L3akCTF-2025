from Crypto.Util.number import inverse, long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

MASK64 = (1 << 64) - 1

def rotl(x, k):
    return ((x << k) | (x >> (64 - k))) & MASK64

def update_state(s):
    s0, s1, s2, s3 = s
    t = (s1 << 17) & MASK64
    s2 ^= s0
    s3 ^= s1
    s1 ^= s2
    s0 ^= s3
    s2 ^= t
    s3 = rotl(s3, 45)
    return [s0, s1, s2, s3]

def temper(raw):
    t = (raw * 5) & MASK64
    t = rotl(t, 7) & MASK64
    return (t * 9) & MASK64

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (Gx, Gy)

def point_add(P, Q):
    if P == (None, None):
        return Q
    if Q == (None, None):
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return (None, None)
    if P == Q:
        l = (3 * x1 * x1 * inverse(2 * y1, p)) % p
    else:
        l = ((y2 - y1) * inverse(x2 - x1, p)) % p
    x3 = (l * l - x1 - x2) % p
    y3 = (l * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k, P):
    R = (None, None)
    while k:
        if k & 1:
            R = point_add(R, P)
        P = point_add(P, P)
        k >>= 1
    return R

leaks = [
    0x785a1cb672480875,
    0x91c1748fec1dd008,
    0x5c52ec3a5931f942,
    0xac4a414750cd93d7
]

# Build matrix
matrix = [0] * 256
for k in range(256):
    word_idx = k // 64
    bit_idx = k % 64
    s = [0] * 4
    s[word_idx] = 1 << bit_idx
    current_s = s[:]
    for output_num in range(4):
        out = current_s[0] ^ current_s[1] ^ current_s[2]
        for bit in range(64):
            if out & (1 << bit):
                row_idx = output_num * 64 + bit
                matrix[row_idx] ^= (1 << k)
        current_s = update_state(current_s)

# Build b
b = []
for leak in leaks:
    for bit in range(64):
        b.append((leak >> bit) & 1)

# Augment matrix with b
for i in range(256):
    matrix[i] |= (b[i] << 256)

# Gauss-Jordan elimination
N = 256
for col in range(N):
    pivot = None
    for row in range(col, N):
        if matrix[row] & (1 << col):
            pivot = row
            break
    if pivot is None:
        raise ValueError("Matrix is singular")
    matrix[col], matrix[pivot] = matrix[pivot], matrix[col]
    for row in range(N):
        if row != col and (matrix[row] & (1 << col)):
            matrix[row] ^= matrix[col]

# Extract solution
initial_bits = [(matrix[i] >> 256) & 1 for i in range(256)]
initial_state = [0] * 4
for k in range(256):
    if initial_bits[k]:
        word_idx = k // 64
        bit_idx = k % 64
        initial_state[word_idx] |= (1 << bit_idx)

# Advance state 4 times
state = initial_state[:]
for _ in range(4):
    state = update_state(state)

# Parameters from output
public_key = (108364470534029284279984867862312730656321584938782311710100671041229823956830, 13364418211739203431596186134046538294475878411857932896543303792197679964862)
h = 9529442011748664341738996529750340456157809966093480864347661556347262857832209689182090159309916943522134394915152900655982067042469766622239675961581701969877932734729317939525310618663767439074719450934795911313281256406574646718593855471365539861693353445695
given_r = 54809455810753652852551513610089439557885757561953942958061085530360106094036
given_s = 42603888460883531054964904523904896098962762092412438324944171394799397690539
ciphertext = '404e9a7bbdac8d3912d881914ab2bdb924d85338fbd1a6d62a88d793b4b9438400489766e8e9fb157c961075ad4421fc'

# Find the correct k
found = False
for attempt in range(100):  # Assuming not too many loops
    raw = state[0] ^ state[1] ^ state[2]
    temp = temper(raw)
    k = temp % n
    state = update_state(state)
    if k == 0:
        continue
    point = scalar_mult(k, G)
    if point[0] is None:
        continue
    r = point[0] % n
    if r == 0:
        continue
    if r == given_r:
        found = True
        break

if not found:
    raise ValueError("No matching k found")

# Recover d
d = ((given_s * k - h) % n * inverse(given_r, n)) % n

# Verify
computed_pub = scalar_mult(d, G)
if computed_pub != public_key:
    raise ValueError("Private key recovery failed")

# Decrypt flag
key = hashlib.sha256(long_to_bytes(d)).digest()
iv = bytes.fromhex(ciphertext[:32])
enc = bytes.fromhex(ciphertext[32:])
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(enc), 16)
print(flag.decode()) 