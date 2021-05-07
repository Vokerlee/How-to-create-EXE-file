# Create-EXE-in-60-minutes
This repo is a guide how to create an executable file in Windows OS. It helps not only to create, but also to understand in more detail how .exe files are arranged.

## Introduction
The structure of .exe file can be considered as follows:
1. [DOS Header](#dos-header)
2. [DOS Stub](#dos-stub)
3. [NT Header](#nt-header)
    * [NT File Header](#nt-file-header)
    * [NT Optional Header](#nt-optional-header)
4. [Sections header](#section-header)
5. [Program segments](program-segments)

So let's figure out what are all these contraptions. Of course, let's deal with DOS thigs first.
## DOS Header
DOS Header is first bytes in our .exe program. Its aim is to describe how the program should act if it is launched under the DOS OS. According to MS source codes, it is the following stuff:
```C++
struct IMAGE_DOS_HEADER {               // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  };
```
Not all these fields are necessary (they can be just filled with zeros). So let's fill the most interesting:
```C++
// =================================================================================================================
e_magic    = 'ZM'       // (in other way "MZ") Must be always filled with this word (Mark Zbikowski — 
                        // a former Microsoft Architect). It is an identifier that our program is 
                        // executable.
// =================================================================================================================
e_cp       = 0x0003     // It's the size of the "entire" MZ format executable (3 pages). This field is 
                        // intended for loading programs under DOS.
// =================================================================================================================                   
e_cblp     = 0x0090     // This value is bytes on last page of file. It means that in DOS anything 
                        // past the last byte in the last page of executable file is ignored. 
                        // When MS-DOS loads an MZ format executable it copies everything in the file 
                        // after the headers up until this limit. So the fact most PE-files have this
                        // field set to a value bigger than the MS-DOS stub (about it read on) just 
                        // means that the PE-file headers' and part of PE-file section data will be 
                        // loaded into memory when the executable is run under MS-DOS.
// =================================================================================================================                        
e_cparhdr  = 0x0004     // The amount of bytes of DOS Header in paragraphes — 64 bytes or 4 paragraphes. 
                        // (Remember about alignment)
// ================================================================================================================= 
e_minalloc = 0x0010     // The minimal amount of dynamic memory you can use.
// ================================================================================================================= 
e_minalloc = 0xFFFF     // The maximum amount of dynamic memory you can use.
// =================================================================================================================
e_sp       = 0x00B8     // Specifies the initial stack pointer value, which is the absolute value that 
                        // must be loaded into the SP register before the program is given control.
// =================================================================================================================                        
e_lfarlc   = 0x0040     // Specifies the file address of the relocation table, or more specifically, 
                        // the offset from the start of the file to the relocation pointer table.
                        // This value must be used to locate the relocation pointer table (rather
                        // than assuming a fixed location) because variable-length information
                        // pertaining to program overlays can occur before this table, causing its
                        // position to vary. A value of 0x40 in this field generally indicates a
                        // different kind of executable file, not a DOS 'MZ' type.
// ================================================================================================================= 
e_lfanew   = 0x00B0     // This field is the address of the beginning of NT Header. So it is the size 
                        // of DOS Header and DOS Stub in bytes (64 + 112 = 176 = 0x00B0).
```
There are two important aims of this header. First of all it is `e_lfanew` — the address of "normal" header that is important for the program, and the second is the description how the program under DOS will behave, using the code from DOS Stub.

## DOS Stub
If you are attentive you already know, that this part is to take 112 bytes. This part of .exe file is to describe the program behaviour under DOS OS. In short, it prints message "This program cannot be run in DOS mode." and exits from the program. So the assemler code is as follows:

```asm
push cs           ; Keep in mind Code Segment(CS) (where we are in memory)
pop ds            ; Data Segment(DS) = Code Segment(CS)

mov dx, 0x0E      ; The address of the string DS+DX, which will be printed until '$' (the end of the string) 
mov ah, 0x09      ; The number of instruction (print regime)
int 0x21          ; 0x21 DOS interrupt

mov ax, 0x4C01    ; The number of instruction 0x4C (exit from the program) 
int 0x21          ; 0x21 DOS interrupt

"This program cannot be run in DOS mode.\x0D\x0A$" ; The output string
```

## NT Header
It is the most important header, because it is directly connected with the work of the program. The components of this header depends on the system capacity. It can be x64 or x86. There are few differences, so let's consider more general case — x86.

```C++
struct IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};
```
Here we can see `Signature`, which role is the same as `e_magic` in DOS Header. It should be "PE" (program executable) or 'EP'. `FileHeader` is common for both x64 and x86. But x64 architecture has `IMAGE_OPTIONAL_HEADER64 OptionalHeader`. Let's look what these headers are.

## NT File Header
This file has the following structure:
```C++
struct IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
}
```
Here the description of each field:
```C++
// =================================================================================================================
Machine = IMAGE_FILE_MACHINE_I386    // The minimal level of machine, which can execute the program. 
                                     // IMAGE_FILE_MACHINE_I386 = 0x014c
                                     // There is no sence to make big demands for execution. (I386 is enough)
                                     // Types of machines you can find here:
                                     // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
// =================================================================================================================
NumberOfSections     = 0x0003        // The number of sections in the program. For example .data section,
                                     // .text and .idata section. Also there are .rdata, .bss and so on.
                                     // This indicates the size of the section table, which immediately 
                                     // follows the headers.
// =================================================================================================================  
TimeDateStamp        = 0x0003        // The low 32 bits of the number of seconds since 00:00 January 1,
                                     // 1970 (a C run-time time_t value), which indicates when the file was created.
// =================================================================================================================
SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32)
                                     // Also can be sizeof(IMAGE_OPTIONAL_HEADER64)
                                     // Remember about alignment!
// =================================================================================================================  
Characteristics      = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
                                     // The flags that indicate the attributes of the file.
                                     // IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
                                     // IMAGE_FILE_32BIT_MACHINE    = 0x0100
                                     // There is no sence to add something more, but if you are interested in 
                                     // you can see it: 
                                     // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
// =================================================================================================================  
```

Okey, continue.

## NT Optional Header

Despite the fact that this header is optional, it is neseccary for .exe file.
The structure of this header:

```C++
struct IMAGE_OPTIONAL_HEADER32 {

    // Standard fields.

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    // NT additional fields.

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
}
```
So there are a lot of fileds, hard work wate for us...
```C++
// =================================================================================================================
Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC   // Similarly can be IMAGE_NT_OPTIONAL_HDR64_MAGIC
                                        // IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b (the most common value).
// =================================================================================================================
ImageBase = 0x00400000                  // It is the address in virtual memory, where the image will be loaded
                                        // 0x00400000 is the most common value (and is default).
                                        // Must be a multiple of 64K!
// =================================================================================================================  
AddressOfEntryPoint = 0x1000            // The address of the entry point relative to the image base when 
                                        // the executable file is loaded into memory. For program images, 
                                        // this is the starting address.
                                        // 0x1000 is the most common value.
// =================================================================================================================
BaseOfCode = 0x1000                     // The address of code section relative to the image base.
                                        // In our guide it is the first section, so it equals to AddressOfEntryPoint.
// ================================================================================================================= 
BaseOfData = 0x1000 + DATA_START        // The address of code section relative to the image base.
                                        // DATA_START is the address of code section relative to the AddressOfEntryPoint
                                        // This value you can count only in the of all headers, so keep it in mind.
// =================================================================================================================
SectionAlignment = 0x1000               // The alignment (in bytes) of sections when they are loaded into memory. 
                                        // It must be greater than or equal to FileAlignment. 
                                        // The default is the page size for the architecture.
// ================================================================================================================= 
SizeOfImage                             // The size (in bytes) of the image, including all headers, as the image is 
                                        // loaded in memory. It must be a multiple of SectionAlignment.
                                        // So headers take 0x1000 size, and if all k sections has the same size in
                                        // virtual memory N, the value of SizeOfImage is 0x1000 + k*N
// ================================================================================================================= 
FileAlignment = 0x200                   // The alignment factor (in bytes) that is used to align the raw data 
                                        // of sections in the image file. The value should be a power of 2 between 
                                        // 512 and 64 K, inclusive. The default is 512. 
                                        // In short, it is the alignment of sections in .exe file.
// ================================================================================================================= 
SizeOfHeaders = 0x400                   // The combined size of an MS-DOS stub, PE header, and section headers 
                                        // rounded up to a multiple of FileAlignment.
// =================================================================================================================
Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI // The subsystem that is required to run this image.
                                        // IMAGE_SUBSYSTEM_WINDOWS_CUI = 3 is a console application.
                                        // IMAGE_SUBSYSTEM_WINDOWS_GUI = 2 is a graphic application.
// =================================================================================================================
NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES
                                        // The number of data-directory entries in the remainder of the optional header. 
                                        // Each describes a location and size.
                                        // IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16 (a default number).
                                        // Read more there:
                                        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
// =================================================================================================================
DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = IMPORT_START;
                                        // IMPORT_START is the address of import data section relative to the AddressOfEntryPoint.
                                        // IMAGE_DIRECTORY_ENTRY_IMPORT = 2.
                                        // It fills the virtual address of import data section. Of course, you can 
                                        // describe all fileds. Read more there:
                                        // https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only
// =================================================================================================================
```
OK, we are too close to finish the .exe file description.
