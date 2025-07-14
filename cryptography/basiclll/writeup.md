# Basic LLL Challenge Writeup

## Challenge Overview

The "Basic LLL" challenge is a cryptographic CTF problem that involves breaking an RSA encryption scheme through a mathematical vulnerability in the key generation process. The challenge name hints at the Lenstra-Lenstra-Lovász (LLL) lattice reduction algorithm, though this specific solution doesn't require LLL directly.

## Challenge Analysis

### Given Information

From the challenge files, we have the following parameters:
- `x = 54203` (16-bit value)
- `a = 139534605978199350449870348663594126359773246906906418074945064315708552206952695156472923968554408862426942537522569163756593332601739006413404986641247624386522169136633429464195370373009454673819688653512479919153332504769835621608305089536245284458011218876474599059184828911301976396971466368457267831713` (1024-bit value)
- `n = p * q` (RSA modulus, 2048-bit)
- `k = x * y + a * p` (relationship between variables)
- `c` (encrypted flag)
- `e = 65537` (RSA public exponent)

### Key Generation Process

Looking at the source code (`basic-lll.sage`), the key generation works as follows:

1. Generate two random 1024-bit primes `p` and `q`
2. Calculate `n = p * q` (RSA modulus)
3. Generate small `x` (16-bit) and `y` (256-bit)
4. Generate large `a` (1024-bit)
5. Calculate `k = x * y + a * p`
6. Encrypt flag using standard RSA: `c = flag^e mod n`

### The Vulnerability

The vulnerability lies in the relationship `k = x * y + a * p`. Since `x` is small (16-bit) and all other values except `y` and `p` are known, we can solve for these unknowns.

## Mathematical Attack

### Step 1: Solve for y

From the equation `k = x * y + a * p`, we can rearrange to:
```
x * y ≡ k (mod a)
y ≡ k * x^(-1) (mod a)
```

Since `gcd(x, a) = 1` (highly likely given the sizes), we can compute the modular inverse of `x` modulo `a`:

```python
x_inv = pow(x, -1, a)
y = (k * x_inv) % a
```

### Step 2: Recover p

Once we have `y`, we can calculate `p`:
```
p = (k - x * y) / a
```

Since `k = x * y + a * p`, this division should be exact.

### Step 3: Factor n

With `p` known, we can easily compute:
```
q = n / p
```

### Step 4: Decrypt the Flag

Now we have the RSA private key components:
```python
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
flag = pow(c, d, n)
```

## Solution Implementation

### Comparison of Two Solutions

Both `solve.py` and `solve2.py` implement the same core algorithm but with different approaches:

**solve.py (Verbose Version):**
- More defensive programming with error handling
- Manual byte conversion using `bit_length()`
- Additional code to extract flag from bytes if needed
- More debugging output

**solve2.py (Concise Version):**
- Clean, straightforward implementation
- Uses `Crypto.Util.number.long_to_bytes()` for conversion
- Includes assertion to verify factorization
- Minimal code with direct output

**Result:** Both scripts produce the same flag: `L3AK{u_4ctu4lly_pwn3d_LLL_w1th_sh0rt_v3ct0rs_n1c3}`

### Why This Attack Works

1. **Small x**: The 16-bit `x` makes the modular arithmetic tractable
2. **Linear relationship**: The equation `k = x * y + a * p` is linear in the unknowns
3. **Known modulus**: Having `a` allows us to work modulo `a` to isolate `y`
4. **Exact division**: Once `y` is found, `p` can be recovered through exact division

## Code Analysis

### Are the Two Solutions the Same?

**Answer: No, but they achieve the same result.**

**Key Differences:**

1. **Mathematical approach slight variation:**
   - `solve.py`: Uses intermediate steps with `y0`, `t` calculations (unnecessarily complex)
   - `solve2.py`: Direct calculation `y = (k * x_inv) % a` (simpler and correct)

2. **Error handling:**
   - `solve.py`: Extensive error handling and debugging
   - `solve2.py`: Minimal, assumes success

3. **Dependencies:**
   - `solve.py`: Pure Python
   - `solve2.py`: Uses `Crypto.Util.number`

4. **Code quality:**
   - `solve.py`: 46 lines, verbose
   - `solve2.py`: 29 lines, concise

**Recommendation:** `solve2.py` is the better implementation - it's cleaner, more direct, and easier to understand.

## Learning Points

1. **Small parameters matter**: Even small values like 16-bit `x` can create significant vulnerabilities
2. **Linear relationships are dangerous**: Equations like `k = x * y + a * p` can be exploited when some variables are known
3. **RSA security depends on factorization**: Once we can factor `n`, RSA is completely broken
4. **Implementation matters**: The same algorithm can be implemented with varying levels of clarity and efficiency

## Mitigation

To prevent this attack:
1. Don't create linear relationships between secret values and known parameters
2. Ensure all secret parameters are sufficiently large
3. Use established cryptographic protocols rather than custom schemes
4. Apply proper security analysis to custom cryptographic constructions

The challenge name "Basic LLL" suggests this could be solved using lattice reduction techniques, but the direct algebraic approach is simpler and more efficient for this particular case. 