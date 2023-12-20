import pefile

def analyze_pe_file(file_path):
    # try:
        pe = pefile.PE(file_path)

        json_res ={}

        json_res['File']= file_path
        json_res['Image Base']= pe.OPTIONAL_HEADER.ImageBase
        json_res['Entry Point']=pe.OPTIONAL_HEADER.AddressOfEntryPoint
        json_res['Sections']= len(pe.sections)
        print(json_res)
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    json_res["Imported_Libraries"].append(entry.dll.decode('utf-8'))
                except:
                    json_res["Imported_Libraries"] = [entry.dll.decode('utf-8')]
        except:
            pass
        try:
            for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                try:
                    json_res["Exported_Symbols"].append(entry.name.decode('utf-8'))
                except:
                    json_res["Exported_Symbols"] = [entry.name.decode('utf-8')]
        except:
            pass
        return json_res
    # except Exception as e:
    #     print(f"An error occurred: {e}")
    #     return {}

import pefile

def analyze_pe_file2(file_path):
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

# if __name__ == "__main__":
#     exe_path = "C:/users/Lenovo/Desktop/ngrok.exe"
#     analyze_pe_file2(exe_path)
