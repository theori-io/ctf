# RISC4: Breaking Reduced Round MD4 Preimage

In this CTF challenge, we explore a vulnerability in a modified MD4 hash implementation running on a RISC Zero zkVM. The challenge demonstrates how reducing the number of rounds in cryptographic hash functions can lead to preimage attacks through constraint solving.

## Challenge Overview

The challenge presents us with a RISC Zero zkVM binary where:
- Input is processed through a reduced-round MD4 hash function
- The hash output must match a specific target value
- The input is limited to 4 bytes
- The binary is compiled for RISC-V architecture

The system implements several standard cryptographic components:
- MD4 hash initialization vectors
- F function: `(x & y) | (~x & z)`
- G function: `(x & y) | (x & z) | (y & z)`
- Standard MD4 rotation constants

The challenge setup provides players with:
- A RISC Zero zkVM binary
- A target hash value to match
- The ability to execute the binary through r0vm

## Initial Code Analysis

Let's examine the core mechanics and key components in detail.

### Input Processing

The binary first processes the 4-byte input through initialization:

```assembly
.text:00201340 lw              s0, 0B4h+var_C(sp)
.text:00201344 addi            a0, sp, 0B4h+chunks+4
.text:00201348 li              a2, 60
.text:0020134C li              a1, 0
.text:00201350 call            memset
.text:00201358 li              a0, 0
.text:0020135C lbu             a1, 1(s0)
.text:00201360 lbu             a2, 0(s0)
.text:00201364 lbu             a3, 2(s0)
.text:00201368 lbu             a4, 3(s0)
```

Key observations:
1. The input is read as a 4-byte value
2. Memory is initialized with standard MD4 constants
3. The initial state vectors are set to standard MD4 values:
   - 0x67452301
   - 0xEFCDAB89
   - 0x98BADCFE
   - 0x10325476

### MD4 Round Implementation

The first round function (F) is implemented as:

```assembly
.text:002013D4 mv              a3, a1
.text:002013D8 mv              a1, a2
.text:002013DC mv              a2, a4
.text:002013E0 and             a4, a1, a4
.text:002013E4 not             t1, a2
.text:002013E8 and             t1, a3, t1
.text:002013EC or              a4, t1, a4
.text:002013F0 andi            t1, a0, 3
.text:002013F4 slli            t1, t1, 2
.text:002013F8 add             t1, a6, t1
.text:002013FC lw              t2, 0(a5)
.text:00201400 lw              t1, 0(t1)
.text:00201404 addi            t3, a0, 1
.text:00201408 add             a4, a4, t0
.text:0020140C add             a4, a4, t2
.text:00201410 neg             a0, t1
.text:00201414 srl             a0, a4, a0
.text:00201418 sll             a4, a4, t1
.text:0020141C or              a4, a4, a0
.text:00201420 addi            a5, a5, 4
.text:00201424 mv              t0, a3
.text:00201428 mv              a0, t3
.text:0020142C bne             t3, a7, loc_2013D4
```

This implements the standard MD4 F function: `(x & y) | (~x & z)`

The second round function (G) follows:

```assembly
.text:002014E0 mv              t4, a1
.text:002014E4 mv              a1, a2
.text:002014E8 mv              a2, a4
.text:002014EC or              a4, t4, a1
.text:002014F0 and             a4, a4, a2
.text:002014F4 and             t5, t4, a1
.text:002014F8 or              a4, a4, t5
.text:002014FC andi            t5, a5, 3
.text:00201500 slli            t5, t5, 2
.text:00201504 add             t5, t0, t5
.text:00201508 lw              t5, 0(t5)
.text:0020150C slli            a0, a0, 2
.text:00201510 add             a0, t1, a0
.text:00201514 lw              a0, 0(a0)
.text:00201518 addi            a5, a5, 1
.text:0020151C add             a3, a3, a4
.text:00201520 add             a3, a3, t2
.text:00201524 add             a0, a3, a0
.text:00201528 neg             a3, t5
.text:0020152C srl             a3, a0, a3
.text:00201530 sll             a4, a0, t5
.text:00201534 or              a4, a4, a3
.text:00201538 addi            a7, a7, 4
.text:0020153C mv              a3, t4
.text:00201540 bne             a5, t3, loc_2014D8
```

This implements the standard MD4 G function: `(x & y) | (x & z) | (y & z)`

### Key Modifications

The most significant changes from the original MD4 implementation are:

1. Limited input size (4 bytes only)
2. Reduced number of rounds
3. Direct comparison with target hash after G round

## Finding the Vulnerability

After analyzing the challenge binary and modifications to the original MD4 algorithm, two key insights emerged:

1. The drastically reduced number of rounds
2. The small input space (32 bits)

The most interesting aspect is how the reduction in rounds affects the cryptographic strength of MD4. While the original MD4 uses three rounds with 16 operations each, this implementation only uses two rounds, significantly weakening its preimage resistance.

## The Exploit

Let's break down the attack step by step.

### Exploit Setup

The exploit requires:
1. Modeling the reduced MD4 operations in Z3
2. Implementing the F and G functions as bit vector operations
3. Setting up constraints for the target hash value

First, we implement the MD4 operations using Z3's bit vector operations:

```python
from z3 import *

s = Solver()

F = lambda x, y, z: (x & y) | (~x & z)
G = lambda x, y, z: (x & y) | (x & z) | (y & z)
```

### Attack Flow

1. Initialize the hash vectors and input:
```python
h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
X = [0 for i in range(16)]
X[0] = BitVec(f'bv', 32)
```

2. Implement Round 1 (F function):
```python
Xi = [3, 7, 11, 19]
for n in range(16):
    i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
    K, S = n, Xi[n % 4]
    hn = h[i] + F(h[j], h[k], h[l]) + X[K]
    h[i] = RotateLeft(hn, S)
```

3. Implement Round 2 (G function):
```python
Xi = [3, 5, 9, 13]
for n in range(16):
    i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
    K, S = n % 4 * 4 + n // 4, Xi[n % 4]
    hn = h[i] + G(h[j], h[k], h[l]) + X[K] + 0x5A827999
    h[i] = RotateLeft(hn, S)
```

4. Add constraints for the target hash:
```python
s.add(h[0] == 0x787aab94)
s.add(h[1] == 0xc4977a27)
s.add(h[2] == 0xd2a30eee)
s.add(h[3] == 0xd264426a)
```

### Why It Works

The exploit succeeds because:
1. The reduced rounds significantly weaken MD4's preimage resistance
2. The small input space makes Z3 constraint solving feasible
3. The operations can be perfectly modeled using bit vectors
4. Z3 can efficiently solve the resulting constraint system

## Complete Solution

```python
from z3 import *

s = Solver()

F = lambda x, y, z: (x & y) | (~x & z)
G = lambda x, y, z: (x & y) | (x & z) | (y & z)

h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
X = [0 for i in range(16)]
X[0] = BitVec(f'bv', 32)

# Round 1.
Xi = [3, 7, 11, 19]
for n in range(16):
    i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
    K, S = n, Xi[n % 4]
    hn = h[i] + F(h[j], h[k], h[l]) + X[K]
    h[i] = RotateLeft(hn, S)

# Round 2.
Xi = [3, 5, 9, 13]
for n in range(16):
    i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
    K, S = n % 4 * 4 + n // 4, Xi[n % 4]
    hn = h[i] + G(h[j], h[k], h[l]) + X[K] + 0x5A827999
    h[i] = RotateLeft(hn, S)

s.add(h[0] == 0x787aab94)
s.add(h[1] == 0xc4977a27)
s.add(h[2] == 0xd2a30eee)
s.add(h[3] == 0xd264426a)

assert s.check() == sat
flag = s.model()[X[0]].as_long()

print(flag.to_bytes(4, 'little').hex())
```

## Key Takeaways

1. Reducing cryptographic rounds can dramatically weaken security
2. Small input spaces make constraint solving attacks feasible
3. Modern SMT solvers can effectively break weakened crypto
4. Bit-perfect modeling enables accurate constraint solving

This challenge demonstrates how modifications to cryptographic primitives, particularly reducing rounds, can enable practical attacks that would be infeasible against the full implementation.