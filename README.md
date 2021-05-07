# Create-EXE-in-20-minutes
This repo is a guide how to create an executable file in Windows OS. 

## Introduction
The structure of .exe file can be considered as follows:
1. DOS Header
2. DOS Stub
3. NT Header
3.1. NT File Header
3.2. NT Optional Header
4. Sections header
5. Program segments

So let's figure out what are all these contraptions. Of course, let's deal with DOS thigs first.
## DOS Header
DOS Header is fisrt bytes in out .exe program. According to MS source codes, it is the following stuff:
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
* e_magic = 'ZM'        // Must be always filled with this word (Mark Zbikowski - a former Microsoft Architect). It is an identifier that our program is executable.
* e_cblp  = 0x0090       //
