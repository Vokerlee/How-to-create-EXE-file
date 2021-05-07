# Create-EXE-in-60-minutes
This repo is a guide how to create an executable file in Windows OS. It helps not only to create, but also to understand in more detail how .exe files are arranged.

## Introduction
The structure of .exe file can be considered as follows:
1. [DOS Header](##dos-header)
2. DOS Stub
3. NT Header
    * NT File Header
    * NT Optional Header
4. Sections header
5. Program segments

So let's figure out what are all these contraptions. Of course, let's deal with DOS thigs first.
## DOS Header
DOS Header is first bytes in out .exe program. Its aim is to describe how the program should act if it is launched under the DOS OS. According to MS source codes, it is the following stuff:
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
e_magic    = 'ZM'       // Must be always filled with this word (Mark Zbikowski — a former Microsoft Architect).
                        // It is an identifier that our program is executable.
// =================================================================================================================
e_cp       = 0x0003     // It's the size of the "entire" MZ format executable (3 pages). This field is intended 
                        // for loading programs under DOS.
// =================================================================================================================                   
e_cblp     = 0x0090     // This value is bytes on last page of file. It means that in DOS anything past the last byte
                        // in the last page of executable file is ignored. When MS-DOS loads an MZ
                        // format executable it copies everything in the file after the headers up
                        // until this limit. So the fact most PE-files have this field set to a
                        // value bigger than the MS-DOS stub (about it read on) just means that
                        // the PE-file headers' and part of PE-file section data will be loaded 
                        // into memory when the executable is run under MS-DOS.
// =================================================================================================================                        
e_cparhdr  = 0x0004     // The amount of bytes of DOS Header in paragraphes — 64 bytes or 4 paragraphes. 
                        // (Remember about alignment)
// ================================================================================================================= 
e_minalloc = 0x0010     // The minimal amount of dynamic memory you can use.
// ================================================================================================================= 
e_minalloc = 0xFFFF     // The maximum amount of dynamic memory you can use.
// =================================================================================================================
e_sp       = 0x00B8     // Specifies the initial stack pointer value, which is the absolute value that must be loaded 
                        // into the SP register before the program is given control.
// =================================================================================================================                        
e_lfarlc   = 0x0040     // Specifies the file address of the relocation table, or more specifically, 
                        // the offset from the start of the file to the relocation pointer table.
                        // This value must be used to locate the relocation pointer table (rather
                        // than assuming a fixed location) because variable-length information
                        // pertaining to program overlays can occur before this table, causing its
                        // position to vary. A value of 0x40 in this field generally indicates a
                        // different kind of executable file, not a DOS 'MZ' type.
// ================================================================================================================= 
e_lfanew   = 0x00B0     // This field is the address of the beginning of NT Header. So it is the size of DOS Header
                        // and DOS Stub in bytes (64 + 112 = 176 = 0x00B0).
```
There are two important aims of this header. First of all it is `e_lfanew` — the address of "normal" header that is important for the program, and the second is the description how the program under DOS will behave, using the code from DOS Stub.

## DOS Stub
