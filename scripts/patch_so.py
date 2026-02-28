#!/usr/bin/env python3
"""
Patch libthing_security.so to disable anti-tampering kills.

Strategy: Patch the PLT stubs for exit(), abort(), and kill() to immediately
return (ret instruction = 0xd65f03c0 in ARM64).

Requirements:
  pip install pyelftools capstone
"""
import argparse
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

import shutil
import sys


# ARM64 RET instruction
ARM64_RET = struct.pack('<I', 0xd65f03c0)
# ARM64 NOP instruction
ARM64_NOP = struct.pack('<I', 0xd503201f)

def find_plt_entries(elf, data):
    """Find PLT entries for exit, abort, kill."""
    results = {}

    # Get .dynsym for symbol names
    dynsym = elf.get_section_by_name('.dynsym')
    if not dynsym:
        print("No .dynsym section")
        return results

    # Build symbol index -> name mapping
    sym_names = {}
    for i, sym in enumerate(dynsym.iter_symbols()):
        sym_names[i] = sym.name

    # Find .rela.plt section - this has relocations for PLT entries
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        if section.name not in ['.rela.plt', '.rel.plt']:
            continue

        print(f"Processing {section.name} ({section.num_relocations()} entries)")
        for rel in section.iter_relocations():
            sym_idx = rel['r_info_sym']
            name = sym_names.get(sym_idx, f"sym_{sym_idx}")
            offset = rel['r_offset']

            if name in ['exit', 'abort', 'kill']:
                results[name] = {
                    'got_offset': offset,
                    'sym_idx': sym_idx,
                }
                print(f"  {name}: GOT offset = 0x{offset:08x}")

    # Now find the PLT section
    plt = elf.get_section_by_name('.plt')
    if plt:
        print(f"\n.plt section: offset=0x{plt['sh_offset']:08x}, size=0x{plt['sh_size']:x}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Patch libthing_security.so to disable anti-tamper")
    parser.add_argument("input", help="Path to libthing_security.so")
    parser.add_argument("-o", "--output", help="Output path (default: <input>_patched.so)")
    args = parser.parse_args()

    so_path = args.input
    out_path = args.output or so_path.replace(".so", "_patched.so")

    shutil.copy(so_path, out_path)

    with open(so_path, 'rb') as f:
        data = bytearray(f.read())

    with open(so_path, 'rb') as f:
        elf = ELFFile(f)

        # Find PLT entries
        got_entries = find_plt_entries(elf, data)

        if not got_entries:
            print("No PLT entries found for exit/abort/kill!")
            return

        # Get the .plt section
        plt_section = elf.get_section_by_name('.plt')
        if not plt_section:
            print("No .plt section found")
            return

        plt_offset = plt_section['sh_offset']
        plt_size = plt_section['sh_size']
        plt_addr = plt_section['sh_addr']

        print(f"\nPLT: file_offset=0x{plt_offset:x}, vaddr=0x{plt_addr:x}, size=0x{plt_size:x}")

        # ARM64 PLT: first entry is resolver (16 bytes), then each stub is 16 bytes
        # Each stub loads from a specific GOT entry
        # Let's decode all PLT stubs and match them to GOT entries
        print("\nDecoding PLT stubs:")
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = True

        stub_size = 16  # Each PLT stub is 16 bytes on ARM64
        first_stub_offset = plt_offset + 32  # Skip PLT header (2 entries = 32 bytes)

        # Decode all stubs
        stubs = {}
        for i in range(0, plt_size - 32, stub_size):
            stub_file_offset = first_stub_offset + i
            stub_vaddr = plt_addr + 32 + i
            stub_code = bytes(data[stub_file_offset:stub_file_offset + stub_size])

            instrs = list(md.disasm(stub_code, stub_vaddr))
            if len(instrs) < 3:
                continue

            # The first instruction is ADRP which loads a page address
            # The second is LDR which loads from an offset within that page
            # Together they form the GOT address
            if instrs[0].mnemonic == 'adrp' and instrs[1].mnemonic == 'ldr':
                # Decode ADRP: page = (PC & ~0xFFF) + (imm << 12)
                adrp_insn = struct.unpack_from('<I', stub_code, 0)[0]
                # immhi = bits[23:5], immlo = bits[30:29]
                immhi = (adrp_insn >> 5) & 0x7ffff
                immlo = (adrp_insn >> 29) & 0x3
                imm = (immhi << 2) | immlo
                # Sign extend 21-bit value
                if imm & (1 << 20):
                    imm |= ~((1 << 21) - 1)
                page = (stub_vaddr & ~0xFFF) + (imm << 12)

                # Decode LDR offset
                ldr_insn = struct.unpack_from('<I', stub_code, 4)[0]
                ldr_offset = ((ldr_insn >> 10) & 0xFFF) << 3  # scale by 8 for 64-bit LDR

                got_target = page + ldr_offset

                # Match to our target functions
                for name, info in got_entries.items():
                    if got_target == info['got_offset']:
                        stubs[name] = {
                            'file_offset': stub_file_offset,
                            'vaddr': stub_vaddr,
                            'got_target': got_target,
                        }
                        print(f"  Stub for {name}: file_offset=0x{stub_file_offset:x}, vaddr=0x{stub_vaddr:x}")

        # Now patch the stubs
        print("\nPatching:")
        for name, info in stubs.items():
            offset = info['file_offset']
            # Replace the entire 16-byte stub with: RET (4 bytes) + 3x NOP
            patch = ARM64_RET + ARM64_NOP * 3
            data[offset:offset+16] = patch
            print(f"  Patched {name} PLT stub at file offset 0x{offset:x} with RET")

        # Write patched binary
        with open(out_path, 'wb') as f:
            f.write(data)
        print(f"\nSaved patched binary to {out_path}")
        print(f"Patched {len(stubs)} PLT stubs")


if __name__ == '__main__':
    main()
