#include <iostream>
#include <Windows.h>
#include <stdlib.h>
#include <tchar.h>
#include <sys/stat.h>
#include <filesystem>
#include <direct.h>

using namespace std;

PTCHAR readFile(PTCHAR fileName) {
    FILE *file;
    fopen_s(&file, fileName, "rb");
    if (nullptr == file) {
        cout << "file open fail" << endl;
        return nullptr;
    }
    struct stat fileStat;
    stat(fileName, &fileStat);
    unsigned int fileSize = fileStat.st_size;
    cout << "file size:" << fileSize << endl;
    auto fileBuffer = (PTCHAR) malloc(fileSize);
    if (nullptr == fileBuffer) {
        cout << "malloc fail" << endl;
        return nullptr;
    }
    memset(fileBuffer, 0, fileSize);
    fread(fileBuffer, fileSize, 1, file);
    fclose(file);
    return fileBuffer;
}

BOOL writeFile(PTCHAR fileBuffer, unsigned long size, PTCHAR newFileName) {
    FILE *file = nullptr;
    file = fopen(newFileName, "wb");
    if (nullptr == file) {
        cout << "file create fail" << endl;
        return FALSE;
    }
    fwrite(fileBuffer, 1, size, file);
    fclose(file);
    return TRUE;
}

PTCHAR fileBufferToImageBuffer(PTCHAR fileBuffer) {
    auto docHeader = (PIMAGE_DOS_HEADER) fileBuffer;
    auto ntHeader = (PIMAGE_NT_HEADERS32) ((PTCHAR) docHeader + docHeader->e_lfanew);
    auto fileHeader = &ntHeader->FileHeader;
    auto optionHeader = &ntHeader->OptionalHeader;
    auto imageBuffer = (PTCHAR) malloc(optionHeader->SizeOfImage);
    memset(imageBuffer, 0, optionHeader->SizeOfImage);
    memcpy(imageBuffer, fileBuffer, optionHeader->SizeOfHeaders);

    for (int i = 0; i < fileHeader->NumberOfSections; i++) {
        auto header = (PIMAGE_SECTION_HEADER) ((PTCHAR) optionHeader + sizeof(*optionHeader) +
                                               (i * IMAGE_SIZEOF_SECTION_HEADER));
        memcpy(imageBuffer + header->VirtualAddress, fileBuffer + header->PointerToRawData,
               header->Misc.VirtualSize);
    }
    return imageBuffer;
}

void imageBufferToFileBuffer(PTCHAR imageBuffer, PTCHAR newFile) {
    auto docHeader = (PIMAGE_DOS_HEADER) imageBuffer;
    auto ntHeader = (PIMAGE_NT_HEADERS32) ((PTCHAR) docHeader + docHeader->e_lfanew);
    auto fileHeader = &ntHeader->FileHeader;
    auto optionHeader = &ntHeader->OptionalHeader;
    auto latestSelectionHeader = (PIMAGE_SECTION_HEADER) ((PTCHAR) optionHeader + sizeof(*optionHeader) +
                                                          ((fileHeader->NumberOfSections - 1) *
                                                           IMAGE_SIZEOF_SECTION_HEADER));
    long fileSize = latestSelectionHeader->PointerToRawData + latestSelectionHeader->SizeOfRawData;
    auto fileBuffer = (PTCHAR) malloc(fileSize);
    memset(fileBuffer, 0, fileSize);
    memcpy(fileBuffer, imageBuffer, optionHeader->SizeOfHeaders);
    for (int i = 0; i < fileHeader->NumberOfSections; i++) {
        auto header = (PIMAGE_SECTION_HEADER) ((PTCHAR) optionHeader + sizeof(*optionHeader) +
                                               (i * IMAGE_SIZEOF_SECTION_HEADER));
        memcpy(fileBuffer + header->PointerToRawData, imageBuffer + header->VirtualAddress,
               header->Misc.VirtualSize);
    }
    writeFile(fileBuffer, fileSize, newFile);
    free(fileBuffer);
}

int main() {

    string currentPath = filesystem::current_path().u8string();

    string fileNameStr = currentPath + R"(\..\resources\Demo.exe)";
    string newFileNameStr = currentPath + R"(\..\resources\Demo-Copy.exe)";

    PTCHAR fileName = fileNameStr.data();
    PTCHAR newFileName = newFileNameStr.data();
    PTCHAR fileBuffer = readFile(fileName);
    PTCHAR imageBuffer = fileBufferToImageBuffer(fileBuffer);//拉伸
    imageBufferToFileBuffer(imageBuffer, newFileName);//压缩

    free(fileBuffer);
    free(imageBuffer);
    return 0;
}
