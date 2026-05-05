# 👻 Ghost in the Vault

**Category:** Reverse Engineering  
**Difficulty:** Easy  
**Flag Format:** `47CON{...}`  

## Description

We intercepted an executable functioning as a digital vault, engineered by a highly paranoid system administrator. Our analysts have tried to extract the secret, but the binary actively defends itself: it lies, alters its behavior if monitored, and refuses to cooperate if you modify a single byte of its code.

Intelligence suggests the admin compiled and sealed this vault on his personal workspace—a completely standard, out-of-the-box setup of his favorite Linux distribution. 

Your objective is to bypass its defenses, understand its execution flow, and recover the original artifact. Do not trust the first thing you see on the screen; sometimes the truth requires digging a few layers deeper.

## Build & Deployment Instructions

To deploy this challenge, you need to compile the C source and then use the provided Python script to encrypt and inject the flag based on the compiled binary's checksum.

### 1. Compile the binary
```bash
gcc -O2 -fomit-frame-pointer -fno-stack-protector -fvisibility=hidden -s GhostInVault.c -o vault

```

### 2. Patch the binary

Run the patcher script once immediately after compiling. This script calculates the real .text checksum, derives the key, and injects the encrypted store[] array into the binary.
```bash
python3 patch_store.py vault
```
You can specify a custom flag or environment targets:
```bash
python3 patch_store.py vault --flag "47CON{y0ur_custom_flag_here!_}" --host "debian" --uid 1000