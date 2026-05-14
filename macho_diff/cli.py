"""
CLI module for the macho-diff tool.
"""
import argparse
import os
import sys

import lief

from macho_diff.helpers import (
    parse_functions,
    compare_instructions,
    generate_batch_patches,
)

lief.logging.disable()


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Mach-O binary visual diff tool")
    parser.add_argument("src", help="Path to the original/source Mach-O binary")
    parser.add_argument("patched", help="Path to the patched Mach-O binary")
    parser.add_argument(
        "-b",
        "--batch",
        action="store_true",
        help="Generate a batch patch file representing the differences.",
    )
    return parser.parse_args()


def load_binary(filepath):
    """Load a Mach-O binary from the given file path."""
    if not os.path.isfile(filepath):
        print(f"Error: File not found: '{filepath}'", file=sys.stderr)
        return None
    try:
        fat = lief.MachO.parse(filepath)
        return fat.at(0) if fat else None
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"Error parsing binary '{filepath}': {e}", file=sys.stderr)
        return None


def read_file_raw(filepath):
    """Read the raw bytes of a file."""
    try:
        with open(filepath, "rb") as f:
            return f.read()
    except OSError as e:
        print(f"Error reading file '{filepath}': {e}", file=sys.stderr)
        return None


def process_diffs(args, binary_src, src_raw, functions_src, functions_patched):
    """Process and print the differences between functions."""
    diff_count = 0
    all_batch_patches = []

    for addr, src_data in functions_src.items():
        patched_data = functions_patched.get(addr)
        if not patched_data:
            continue

        if src_data["checksum"] != patched_data["checksum"]:
            if args.batch:
                patches = generate_batch_patches(
                    binary_src, src_raw, addr, src_data["data"], patched_data["data"]
                )
                if patches:
                    all_batch_patches.append((src_data["name"], patches))
            else:
                print(
                    f"\n[DIFF] {src_data['name']} @ {hex(addr)} size={src_data['size']}"
                )
                compare_instructions(
                    binary_src, addr, src_data["data"], patched_data["data"]
                )
            diff_count += 1

    return diff_count, all_batch_patches


def print_batch_patches(binary_src, all_batch_patches):
    """Print the batch patches."""
    cputype_name = binary_src.header.cpu_type.name
    print("\nBatch Patches:" + "\n" + "=" * 40)
    print(f"{cputype_name}:\n")

    for _, patches in all_batch_patches:
        for find_str, replace_str in patches:
            print(find_str)
            print("to")
            print(replace_str)
            print()
    print("=" * 40)


def main():
    """Main entry point for the CLI."""
    args = parse_args()

    print(f"Loading '{args.src}'...")
    binary_src = load_binary(args.src)
    if not binary_src:
        return

    print(f"Loading '{args.patched}'...")
    binary_patched = load_binary(args.patched)
    if not binary_patched:
        return

    print("Reading file contents...")
    src_raw = read_file_raw(args.src)
    if not src_raw:
        return
    patched_raw = read_file_raw(args.patched)
    if not patched_raw:
        return

    print("Parsing functions (this might take a moment)...")
    functions_src = parse_functions(binary_src, src_raw)
    functions_patched = parse_functions(binary_patched, patched_raw)

    print(
        f"Found {len(functions_src)} functions in source binary "
        f"and {len(functions_patched)} in patched binary."
    )

    diff_count, all_batch_patches = process_diffs(
        args, binary_src, src_raw, functions_src, functions_patched
    )

    if args.batch:
        print_batch_patches(binary_src, all_batch_patches)

    print(f"\nTotal diffs: {diff_count}")


if __name__ == "__main__":
    main()
