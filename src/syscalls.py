import ctypes
import ctypes.wintypes as wintypes
import sys

# constants
IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_DIRECTORY_ENTRY_EXPORT = 0  # export table index
MAX_STUB_BYTES = 0x40  

# basic structures used for both 32/64 parsing
class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ("e_magic", wintypes.WORD),
        ("e_cblp", wintypes.WORD),
        ("e_cp", wintypes.WORD),
        ("e_crlc", wintypes.WORD),
        ("e_cparhdr", wintypes.WORD),
        ("e_minalloc", wintypes.WORD),
        ("e_maxalloc", wintypes.WORD),
        ("e_ss", wintypes.WORD),
        ("e_sp", wintypes.WORD),
        ("e_csum", wintypes.WORD),
        ("e_ip", wintypes.WORD),
        ("e_cs", wintypes.WORD),
        ("e_lfarlc", wintypes.WORD),
        ("e_ovno", wintypes.WORD),
        ("e_res", wintypes.WORD * 4),
        ("e_oemid", wintypes.WORD),
        ("e_oeminfo", wintypes.WORD),
        ("e_res2", wintypes.WORD * 10),
        ("e_lfanew", wintypes.LONG)
    ]

class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ("Machine", wintypes.WORD),
        ("NumberOfSections", wintypes.WORD),
        ("TimeDateStamp", wintypes.DWORD),
        ("PointerToSymbolTable", wintypes.DWORD),
        ("NumberOfSymbols", wintypes.DWORD),
        ("SizeOfOptionalHeader", wintypes.WORD),
        ("Characteristics", wintypes.WORD)
    ]

class IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("VirtualAddress", wintypes.DWORD),
        ("Size", wintypes.DWORD)
    ]

class IMAGE_OPTIONAL_HEADER32(ctypes.Structure):
    _fields_ = [
        ("Magic", wintypes.WORD),
        ("MajorLinkerVersion", ctypes.c_ubyte),
        ("MinorLinkerVersion", ctypes.c_ubyte),
        ("SizeOfCode", wintypes.DWORD),
        ("SizeOfInitializedData", wintypes.DWORD),
        ("SizeOfUninitializedData", wintypes.DWORD),
        ("AddressOfEntryPoint", wintypes.DWORD),
        ("BaseOfCode", wintypes.DWORD),
        ("BaseOfData", wintypes.DWORD),
        ("ImageBase", wintypes.DWORD),
        ("SectionAlignment", wintypes.DWORD),
        ("FileAlignment", wintypes.DWORD),
        ("MajorOperatingSystemVersion", wintypes.WORD),
        ("MinorOperatingSystemVersion", wintypes.WORD),
        ("MajorImageVersion", wintypes.WORD),
        ("MinorImageVersion", wintypes.WORD),
        ("MajorSubsystemVersion", wintypes.WORD),
        ("MinorSubsystemVersion", wintypes.WORD),
        ("Win32VersionValue", wintypes.DWORD),
        ("SizeOfImage", wintypes.DWORD),
        ("SizeOfHeaders", wintypes.DWORD),
        ("CheckSum", wintypes.DWORD),
        ("Subsystem", wintypes.WORD),
        ("DllCharacteristics", wintypes.WORD),
        ("SizeOfStackReserve", wintypes.DWORD),
        ("SizeOfStackCommit", wintypes.DWORD),
        ("SizeOfHeapReserve", wintypes.DWORD),
        ("SizeOfHeapCommit", wintypes.DWORD),
        ("LoaderFlags", wintypes.DWORD),
        ("NumberOfRvaAndSizes", wintypes.DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * 16)
    ]

class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
    _fields_ = [
        ("Magic", wintypes.WORD),
        ("MajorLinkerVersion", ctypes.c_ubyte),
        ("MinorLinkerVersion", ctypes.c_ubyte),
        ("SizeOfCode", wintypes.DWORD),
        ("SizeOfInitializedData", wintypes.DWORD),
        ("SizeOfUninitializedData", wintypes.DWORD),
        ("AddressOfEntryPoint", wintypes.DWORD),
        ("BaseOfCode", wintypes.DWORD),
        ("ImageBase", ctypes.c_ulonglong),
        ("SectionAlignment", wintypes.DWORD),
        ("FileAlignment", wintypes.DWORD),
        ("MajorOperatingSystemVersion", wintypes.WORD),
        ("MinorOperatingSystemVersion", wintypes.WORD),
        ("MajorImageVersion", wintypes.WORD),
        ("MinorImageVersion", wintypes.WORD),
        ("MajorSubsystemVersion", wintypes.WORD),
        ("MinorSubsystemVersion", wintypes.WORD),
        ("Win32VersionValue", wintypes.DWORD),
        ("SizeOfImage", wintypes.DWORD),
        ("SizeOfHeaders", wintypes.DWORD),
        ("CheckSum", wintypes.DWORD),
        ("Subsystem", wintypes.WORD),
        ("DllCharacteristics", wintypes.WORD),
        ("SizeOfStackReserve", ctypes.c_ulonglong),
        ("SizeOfStackCommit", ctypes.c_ulonglong),
        ("SizeOfHeapReserve", ctypes.c_ulonglong),
        ("SizeOfHeapCommit", ctypes.c_ulonglong),
        ("LoaderFlags", wintypes.DWORD),
        ("NumberOfRvaAndSizes", wintypes.DWORD),
        ("DataDirectory", IMAGE_DATA_DIRECTORY * 16)
    ]

class IMAGE_NT_HEADERS32(ctypes.Structure):
    _fields_ = [
        ("Signature", wintypes.DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER32)
    ]

class IMAGE_NT_HEADERS64(ctypes.Structure):
    _fields_ = [
        ("Signature", wintypes.DWORD),
        ("FileHeader", IMAGE_FILE_HEADER),
        ("OptionalHeader", IMAGE_OPTIONAL_HEADER64)
    ]

class IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("Characteristics", wintypes.DWORD),
        ("TimeDateStamp", wintypes.DWORD),
        ("MajorVersion", wintypes.WORD),
        ("MinorVersion", wintypes.WORD),
        ("Name", wintypes.DWORD),
        ("Base", wintypes.DWORD),
        ("NumberOfFunctions", wintypes.DWORD),
        ("NumberOfNames", wintypes.DWORD),
        ("AddressOfFunctions", wintypes.DWORD),
        ("AddressOfNames", wintypes.DWORD),
        ("AddressOfNameOrdinals", wintypes.DWORD)
    ]

def get_module_base(module_name: str):
    h = ctypes.windll.kernel32.GetModuleHandleW(module_name)
    if not h:
        raise OSError(f"GetModuleHandleW failed for {module_name}")
    return h

def read_cstring_from_address(addr):
    try:
        result = bytearray()
        i = 0
        while True:
            byte = ctypes.c_ubyte.from_address(addr + i).value
            if byte == 0:
                break
            result.append(byte)
            i += 1
        return bytes(result)
    except (ValueError, OSError):
        return None

def parse_exports(module_base):
    base = module_base
    dos = IMAGE_DOS_HEADER.from_address(base)
    if dos.e_magic != IMAGE_DOS_SIGNATURE:
        raise RuntimeError("invalid dos signature")

    nt_header_addr = base + dos.e_lfanew
    sig = ctypes.c_uint32.from_address(nt_header_addr).value
    if sig != IMAGE_NT_SIGNATURE:
        raise RuntimeError("invalid nt signature")

    file_header = IMAGE_FILE_HEADER.from_address(nt_header_addr + 4)
    opt_magic = ctypes.c_uint16.from_address(nt_header_addr + 4 + ctypes.sizeof(IMAGE_FILE_HEADER)).value

    is_64bit = (opt_magic == 0x20b)  # 0x10b = pe32, 0x20b = pe32+
    if is_64bit:
        nt = IMAGE_NT_HEADERS64.from_address(nt_header_addr)
        opt = nt.OptionalHeader
    else:
        nt = IMAGE_NT_HEADERS32.from_address(nt_header_addr)
        opt = nt.OptionalHeader

    if opt.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT:
        raise RuntimeError("no data directories")

    export_dir_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    if not export_dir_rva:
        raise RuntimeError("no export directory")

    export_dir_addr = base + export_dir_rva
    export_dir = IMAGE_EXPORT_DIRECTORY.from_address(export_dir_addr)

    num_names = export_dir.NumberOfNames
    num_funcs = export_dir.NumberOfFunctions
    aof_addr = base + export_dir.AddressOfFunctions
    aon_addr = base + export_dir.AddressOfNames
    ao_no_addr = base + export_dir.AddressOfNameOrdinals

    AddressOfFunctions = (wintypes.DWORD * num_funcs).from_address(aof_addr) if num_funcs else []
    AddressOfNames = (wintypes.DWORD * num_names).from_address(aon_addr) if num_names else []
    AddressOfNameOrdinals = (wintypes.WORD * num_names).from_address(ao_no_addr) if num_names else []

    results = []
    for i in range(num_names):
        try:
            name_rva = AddressOfNames[i]
            name_addr = base + name_rva
            func_name = read_cstring_from_address(name_addr)
            if not func_name:
                continue
            if not func_name.startswith(b"Nt"):
                continue
            ordinal_index = AddressOfNameOrdinals[i] 
            func_rva = AddressOfFunctions[ordinal_index]
            results.append((func_name.decode(), func_rva, ordinal_index))
        except Exception:
            continue

    return results, is_64bit, base

def extract_syscall_from_stub(stub_addr, is_64bit):
    try:
        data = (ctypes.c_ubyte * MAX_STUB_BYTES).from_address(stub_addr)
    except (ValueError, OSError):
        return None

    b = bytes(data)
    for i in range(0, min(len(b)-4, 32)):
        if b[i] == 0xB8:
            imm = int.from_bytes(b[i+1:i+5], "little")
            if imm < 0x10000:
                return imm
            return imm  # still return; caller can validate
    # on x64 there may be opcode sequence: mov r10, rcx (4c 8b d1) then mov eax, imm32
    # above scan will catch the b8 anyway; so fallback None
    return None

def main():
    try:
        module_base = get_module_base("ntdll.dll")
    except Exception as e:
        print("failed to get ntdll base:", e)
        sys.exit(1)

    try:
        exports, is_64bit, base = parse_exports(module_base)
    except Exception as e:
        print("failed to parse exports:", e)
        sys.exit(1)

    syscalls = {}
    for name, func_rva, ordinal_index in exports:
        func_addr = base + func_rva
        sc = extract_syscall_from_stub(func_addr, is_64bit)
        if sc is not None:
            syscalls[name] = sc

    # write output file
    out_path = "ntdll_syscalls.py"
    with open(out_path, "w", newline="\n") as f:
        f.write("# autogenerated ntdll syscall stubs\n")
        f.write("# generated by script\n\n")
        f.write("syscalls = {\n")
        for k, v in sorted(syscalls.items(), key=lambda kv: kv[0].lower()):
            f.write(f"    {k!r}: {v},\n")
        f.write("}\n")

    print(f"wrote {len(syscalls)} syscalls to {out_path}")

if __name__ == "__main__":
    main()

