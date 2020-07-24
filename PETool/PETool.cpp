

#include <iostream>
#include <stdio.h>
#include <windows.h>

#include <winnt.h>




int openWithCLib(const char* filePath) {
    FILE* pFile = fopen(filePath, "rb");

    if (pFile == NULL) {
        return -1;
    }

    fseek(pFile, 0, SEEK_END);

    long fileSize = ftell(pFile);
    fseek(pFile, 0, SEEK_SET);

    unsigned char* pByte = (unsigned char*)malloc(fileSize);

    if (pByte != NULL) {
        fread(pByte, fileSize, 1, pFile);

        free(pByte);
    }

    fclose(pFile);
    return 0;
}

int openFileWithWindowsAPI(const char* filePath) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

    if (hMap == NULL) {
        return -1;
    }

    LPBYTE lpBase = (LPBYTE)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    if (lpBase == NULL) {
        return -1;
    }

    UnmapViewOfFile(lpBase);

    CloseHandle(hMap);

    CloseHandle(hFile);

    return 0;
}

int get_size_image_dos_header() {
    int a = sizeof(_IMAGE_DOS_HEADER);
    return a;
}




DWORD rva_to_foa(IMAGE_SECTION_HEADER* section_header, WORD num_sections, DWORD rva) {
    DWORD foa = 0;


    int index = -1;
    IMAGE_SECTION_HEADER* sh = NULL;
    for (int i = 0; i < num_sections; i++) {
        sh = section_header + i;
        if (rva >= sh->VirtualAddress && rva < sh->VirtualAddress + sh->SizeOfRawData) {
            index = i;
            break;
        }
    }

    if (index >= 0) {
        foa = rva - sh->VirtualAddress + sh->PointerToRawData;
    }



    return foa;
}

void print_import_table(unsigned char* pByte, _IMAGE_NT_HEADERS* nt_header) {
    IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_header);
    WORD num_sections = nt_header->FileHeader.NumberOfSections;
    DWORD entry_import_rva = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD entry_import_foa = rva_to_foa(section_header, num_sections, entry_import_rva);

    IMAGE_IMPORT_DESCRIPTOR* entry_import = (IMAGE_IMPORT_DESCRIPTOR*)(pByte + entry_import_foa);

    while (entry_import->Name != NULL) {

        char* dll_name = (char*)(pByte + rva_to_foa(section_header, num_sections, entry_import->Name));
        printf("-----dll import-------\n");
        printf("dll name is %s\n", dll_name);
        IMAGE_THUNK_DATA32* thunk_data = (IMAGE_THUNK_DATA32*)(pByte + rva_to_foa(section_header, num_sections, entry_import->OriginalFirstThunk));

        while (thunk_data->u1.Ordinal != NULL) {

            if (IMAGE_SNAP_BY_ORDINAL32(thunk_data->u1.Ordinal)) {
                int import_index = IMAGE_ORDINAL32(thunk_data->u1.Ordinal);
            }
            else {
                IMAGE_IMPORT_BY_NAME* iin = (IMAGE_IMPORT_BY_NAME*)(pByte + rva_to_foa(section_header, num_sections, thunk_data->u1.Function));

                printf("function name %s\r\n", iin->Name);
            }

            thunk_data++;
        }

        entry_import++;
    }

}

void decode_image_file_header(_IMAGE_NT_HEADERS* nt_header) {
    _IMAGE_FILE_HEADER* fileHeader = &nt_header->FileHeader;

    if (fileHeader->Machine == IMAGE_FILE_MACHINE_I386) {
        printf("I386\n");
    }
    WORD num_section = fileHeader->NumberOfSections;
    printf("NumberOfSections %i\n", num_section);

    const int exe_mark = IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LOCAL_SYMS_STRIPPED | IMAGE_FILE_32BIT_MACHINE;
    if (fileHeader->Characteristics == exe_mark) {
        printf("exe\n");
    }

    _IMAGE_OPTIONAL_HEADER* optional_header = &nt_header->OptionalHeader;

    switch (optional_header->Magic)
    {
       case(IMAGE_NT_OPTIONAL_HDR32_MAGIC): {
          printf("32 bit\n");
          break;
       }

       case(IMAGE_NT_OPTIONAL_HDR64_MAGIC): {
           printf("64 bit\n");
           break;
       }
        
        default:
           break;
    }

    

    IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt_header);

    for (int i = 0; i < num_section; i++) {
        IMAGE_SECTION_HEADER* sh = section_header + i;
        BYTE* name = sh->Name;
        DWORD v_size = sh->Misc.VirtualSize;
        DWORD v_address = sh->VirtualAddress;
        DWORD size_raw_data = sh->SizeOfRawData;
        DWORD p_raw_data = sh->PointerToRawData;
        DWORD Characteristics = sh->Characteristics;

        printf("-----------");
        printf("section name %s, v_size %d, raw_size %d \n", name, v_size, size_raw_data);


    }

    DWORD foa = rva_to_foa(section_header, num_section, 0x105B);




    int o = 0;
}

int check_if_pe(const char* filePath) {

    
    FILE* pFile = fopen(filePath, "rb");

    if (pFile == NULL) {
        printf("open file failed\n");
        return -1;
    }

    fseek(pFile, 0, SEEK_END);

    long fileSize = ftell(pFile);
    fseek(pFile, 0, SEEK_SET);

    unsigned char* pByte = (unsigned char*)malloc(fileSize);

    if (pByte != NULL && fileSize > sizeof(_IMAGE_DOS_HEADER)) {
        fread(pByte, 1, fileSize, pFile);
        _IMAGE_DOS_HEADER* dosHeader = (_IMAGE_DOS_HEADER*)pByte;



        if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
            _IMAGE_NT_HEADERS* nt_header = (_IMAGE_NT_HEADERS*)(pByte + dosHeader->e_lfanew);

            if (nt_header->Signature == IMAGE_NT_SIGNATURE) {
                decode_image_file_header(nt_header);


                print_import_table(pByte, nt_header);

                return 1;
            }
            else {
                return -1;
            }
        }
        else {
            return -1;
        }

        free(pByte);
    }

    fclose(pFile);
    return 0;
}




int main(int argc, char* argv[])
{
    if (argc <= 1) {
        printf("please input a file path");
        exit(-1);
    }
    const char* filePath = argv[1];

    check_if_pe(filePath);

    return 0;
}

