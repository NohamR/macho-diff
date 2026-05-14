"""
Helper functions for macho-diff tool.
"""
import hashlib
import capstone


def va_to_file_offset(binary, va):
    """Convert a virtual address to a file offset."""
    for segment in binary.segments:
        start = segment.virtual_address
        end = start + segment.virtual_size

        if start <= va < end:
            delta = va - start
            return segment.file_offset + delta
    return None


def get_function_bytes(binary, raw_data, address, size):
    """Retrieve the raw bytes for a function given its virtual address and size."""
    if size <= 0:
        return b""
    file_offset = va_to_file_offset(binary, address)
    if file_offset is None:
        return b""
    end = file_offset + size
    if end > len(raw_data):
        size = len(raw_data) - file_offset
    if size <= 0:
        return b""
    return raw_data[file_offset : file_offset + size]


def checksum(data):
    """Calculate the SHA256 checksum of the given data."""
    return hashlib.sha256(data).hexdigest()


def parse_functions(binary, raw_data):
    """Parse and extract functions from a Mach-O binary."""
    funcs = sorted(binary.functions, key=lambda f: f.address)
    out = {}
    for i in range(len(funcs) - 1):
        cur, nxt = funcs[i], funcs[i + 1]
        addr, next_addr = cur.address, nxt.address
        if next_addr <= addr:
            continue
        size = next_addr - addr
        if size > 0x100000:
            continue
        name = cur.name or f"sub_{addr:x}"

        data = get_function_bytes(binary, raw_data, addr, size)
        if not data:
            continue
        out[addr] = {
            "name": name,
            "size": size,
            "data": data,
            "start": hex(addr),
            "end": hex(next_addr - 4),
            "checksum": checksum(data),
        }
    return out


def find_nearest_function(functions, target_addr):
    """Find the function that encompasses or immediately precedes the target address."""
    closest_addr = None
    for addr in sorted(functions.keys()):
        if addr <= target_addr:
            closest_addr = addr
        else:
            break

    if closest_addr is not None:
        return closest_addr, functions[closest_addr]
    return None, None


def get_capstone_context(binary):
    """Initialize a capstone disassembler context for the binary architecture."""
    cputype = binary.header.cpu_type
    if cputype.name == "ARM64":
        arch = capstone.CS_ARCH_ARM64
        mode = capstone.CS_MODE_ARM
    elif cputype.name == "ARM":
        arch = capstone.CS_ARCH_ARM
        mode = capstone.CS_MODE_ARM
    elif cputype.name == "X86_64":
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_64
    elif cputype.name == "X86":
        arch = capstone.CS_ARCH_X86
        mode = capstone.CS_MODE_32
    else:
        raise ValueError(f"Unsupported CPU type: {cputype.name}")

    return capstone.Cs(arch, mode)


def _get_diff_blocks(src_insns, patched_insns):
    """Identify contiguous blocks of differing instructions."""
    max_len = max(len(src_insns), len(patched_insns))
    blocks = []
    current_block = []

    for i in range(max_len):
        src_i = src_insns[i] if i < len(src_insns) else None
        patch_i = patched_insns[i] if i < len(patched_insns) else None

        src_str = f"{src_i.mnemonic} {src_i.op_str}" if src_i else "<none>"
        patch_str = f"{patch_i.mnemonic} {patch_i.op_str}" if patch_i else "<none>"

        if src_str != patch_str:
            current_block.append(i)
        else:
            if current_block:
                blocks.append((current_block[0], current_block[-1]))
                current_block = []

    if current_block:
        blocks.append((current_block[0], current_block[-1]))

    return blocks


def _expand_and_format_patches(src_raw, src_insns, patched_insns, blocks):
    """Expand each differing block until unique, and return formatted hex patches."""
    # pylint: disable=too-many-locals
    patches = []
    for start_idx, end_idx in blocks:
        curr_start = start_idx
        curr_end = end_idx

        while True:
            find_bytes = b"".join(
                bytes(src_insns[j].bytes)
                for j in range(curr_start, curr_end + 1)
                if j < len(src_insns)
            )

            if src_raw.count(find_bytes) <= 1:
                break

            can_expand_left = curr_start > 0
            can_expand_right = (
                curr_end < len(src_insns) - 1 and curr_end < len(patched_insns) - 1
            )

            if not can_expand_left and not can_expand_right:
                break

            if can_expand_left:
                curr_start -= 1
            elif can_expand_right:
                curr_end += 1

        find_hex = []
        replace_hex = []
        for j in range(curr_start, curr_end + 1):
            src_i = src_insns[j] if j < len(src_insns) else None
            patch_i = patched_insns[j] if j < len(patched_insns) else None
            if src_i:
                find_hex.extend(f"{b:02X}" for b in src_i.bytes)
            if patch_i:
                replace_hex.extend(f"{b:02X}" for b in patch_i.bytes)
        patches.append((" ".join(find_hex), " ".join(replace_hex)))

    return patches


def generate_batch_patches(binary, src_raw, addr, src_bytes, patched_bytes):
    """Generate batch patches comparing two sets of function bytes."""
    md = get_capstone_context(binary)
    src_insns = list(md.disasm(src_bytes, addr))
    patched_insns = list(md.disasm(patched_bytes, addr))

    blocks = _get_diff_blocks(src_insns, patched_insns)
    return _expand_and_format_patches(src_raw, src_insns, patched_insns, blocks)


def compare_instructions(binary, addr, src_bytes, patched_bytes):
    """Print the differences between two instruction streams."""
    md = get_capstone_context(binary)
    src_insns = list(md.disasm(src_bytes, addr))
    patched_insns = list(md.disasm(patched_bytes, addr))

    max_len = max(len(src_insns), len(patched_insns))
    last_diff_idx = None
    for i in range(max_len):
        src_i = src_insns[i] if i < len(src_insns) else None
        patch_i = patched_insns[i] if i < len(patched_insns) else None

        src_str = f"{src_i.mnemonic} {src_i.op_str}" if src_i else "<none>"
        patch_str = f"{patch_i.mnemonic} {patch_i.op_str}" if patch_i else "<none>"

        if src_str != patch_str:
            if last_diff_idx is not None and i > last_diff_idx + 1:
                print("  ...")
            curr_addr = (
                src_i.address if src_i else (patch_i.address if patch_i else addr)
            )
            print(f"  {hex(curr_addr)}: {src_str:<35} | patch: {patch_str}")
            last_diff_idx = i
