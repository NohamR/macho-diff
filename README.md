# macho-diff

A command-line tool for visualizing instruction-level differences between Mach-O binaries. It uses `LIEF` to parse the Mach-O structure and `capstone` to disassemble and compare functions byte-by-byte and instruction-by-instruction.

## Features

- **Architecture Support:** Supports ARM64, ARM, X86_64, and X86.
- **Function Checksums:** Quickly identifies modified functions via SHA-256 byte hashing.
- **Instruction-Level Diff:** Identifies the exact mnemonic and operand differences between the original and patched binaries directly in the CLI.
- **Batch Patches:** Automatically generates batch hexadecimal patches which ensure unique byte patterns for safe find-and-replace patching across binaries. The batch notes output is fully compatible with [Amimod](https://github.com/EshayDev/Amimod).

## Installation

Assuming you are using [`uv`](https://github.com/astral-sh/uv) (or standard `pip`):

```bash
git clone https://NohamR/macho-diff && cd macho-diff

uv sync
```

## Usage

Run the tool by passing the source and patched Mach-O binaries:

```bash
uv run macho-diff <source_binary> <patched_binary>
```

```bash
uv run macho-diff <source_binary> <patched_binary> -b
```