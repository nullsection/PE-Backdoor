import pefile
import argparse

def find_code_caves(pe_path, min_size=100):
    pe = pefile.PE(pe_path)
    caves = []

    for section in pe.sections:
        section_name = section.Name.decode(errors='ignore').strip('\x00')
        raw_data = section.get_data()
        raw_offset = section.PointerToRawData
        virt_addr = section.VirtualAddress
        virt_size = section.Misc_VirtualSize

        current_len = 0
        start = None

        for i in range(len(raw_data)):
            if raw_data[i] == 0x00:
                if current_len == 0:
                    start = i
                current_len += 1
            else:
                if current_len >= min_size:
                    rva = virt_addr + start
                    va = pe.OPTIONAL_HEADER.ImageBase + rva
                    if (start + current_len) <= virt_size:
                        caves.append({
                            'section': section_name,
                            'rva': rva,
                            'va': va,
                            'file_offset': raw_offset + start,
                            'size': current_len
                        })
                current_len = 0
                start = None

        # trailing nulls at end of section
        if current_len >= min_size and (start + current_len) <= virt_size:
            rva = virt_addr + start
            va = pe.OPTIONAL_HEADER.ImageBase + rva
            caves.append({
                'section': section_name,
                'rva': rva,
                'va': va,
                'file_offset': raw_offset + start,
                'size': current_len
            })

    return caves

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to EXE or DLL")
    parser.add_argument("--min", type=int, default=100, help="Minimum cave size in bytes")
    args = parser.parse_args()

    caves = find_code_caves(args.input, args.min)
    if not caves:
        print("[-] No suitable code caves found.")
    else:
        for c in caves:
            print(f"[+] Section: {c['section']:<8} | RVA: 0x{c['rva']:08X} | VA: 0x{c['va']:016X} | Offset: 0x{c['file_offset']:08X} | Size: {c['size']} bytes")
