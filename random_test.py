import pefile

def analyze_pe_file(file_path):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)

        # Print basic information
        print(f"File: {file_path}")
        print(f"Image Base: 0x{pe.OPTIONAL_HEADER.ImageBase:08X}")
        print(f"Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
        print(f"Sections: {len(pe.sections)}")

        # Print imported libraries
        print("\nImported Libraries:")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"- {entry.dll.decode('utf-8')}")

        # Print exported symbols
        print("\nExported Symbols:")
        for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(f"- {entry.name.decode('utf-8')}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    exe_path = "C:/users/Lenovo/Desktop/vsc.exe"
    analyze_pe_file(exe_path)
