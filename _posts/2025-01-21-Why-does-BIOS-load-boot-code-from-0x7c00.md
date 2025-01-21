---
layout: post
title: Why does BIOS load boot code from 0x7c00?
date: 2025-01-21
---

If you research BIOS and MBR conventions, you'll find lot of "insider knowledge" without many back-references or primary sources. This will only get worse as systems migrate to UEFI, and MBR is laid to rest with cassette tapes and CD players. For now, we can expect to live with MBR BIOS for some period of time, so there is still some merit in researching its conventions.

One such convention is the loading and executing MBR code from, specifically, location 0x7c00. You'll notice this virtual offset is accounted for, hardcoded into nearly all boot code. You won't see this type of hardcoding in typical PE or ELF files, which define their own virtual memory address, and which may even struggle to load hardcoded locations in this way.

I found this "magic number" interesting because its history is ambiguous. For such an integral part of the boot process, there's no formal standard that states this as a requirement. In the most technical sense, BIOS code "may" boot anywhere, but most of them jump to this location in memroy. Why is that?

First, let's check out the Wikipedia page for BIOS:

> The name originates from the Basic Input/Output System used in the CP/M operating system in 1975. The BIOS firmware was originally proprietary to the IBM PC; it was reverse engineered by some companies (such as Phoenix Technologies) looking to create compatible systems. *The interface of that original system serves as a de facto standard.* 

The bit about a "de facto standard" plays an interesting role in the history of BIOS, dating all the way to 1975. We can see that one overarching goal many of these engineers was to enable compatibility among systems. 

You'll often see this in real-world software development as a way to save time (by not reinventing the wheel). It gives you a kind of working standard. You can streamline the time and effort that goes into debugging or developing code. As a low-level, 16-bit BIOS developer, it's good to know that your boot code will always start at the same location, even if there's no official document which defines where it "must" start.

Still, if you go looking, you're not likely to find much about the standardization of 0x7c00 in 1975. How did it become a *de facto* one? Who started it?

[Most](https://www.glamenv-septzen.net/en/view/6?utm_source=chatgpt.com) [researchers](https://ukscott.blogspot.com/2016/11/why-bios-loads-mbr-into-0x7c00-in-x86.html) attribute the very first instance of this to the IBM PC 5150, "the ancestor of modern x86 (32bit) IBM PC/AT Compatible PCs," made in 1981. This is  six years after the CP/M BIOS firmware was originally reverse engineered.

You'll notice the magic number appear in two contexts: BIOS memory maps, and calls to `INT 19H`. I wanted to find out more, so I found the [Technical Reference guide](https://bitsavers.org/pdf/ibm/pc/pc/6025008_PC_Technical_Reference_Aug81.pdf) for this exact system. 

The guide itself is pretty old, a scan of a document that dates back to 1981. Unfortunately, this leaves the modern reader with OCR-based text rendering, which doesn't play nicely with searching, copying, or pasting. For convenience, I've transcribed the [INT 19H listing here](https://gist.github.com/halcyondream/93726fe6877a6f48ee50c417f38740a3). If you have questions beyond what was transcribed, you'll need to read the manual.

First, it's worth noting that the BIOS memory map on page 3-7 (171 in the PDF) lays out a simple blueprint:

| Starting Address Hex | Description                 |
| -------------------- | --------------------------- |
| 00000                | BIOS INTERRUPT VECTORS      |
| 00080                | AVAILABLE INTERRUPT VECTORS |
| 00400                | BIOS DATA AREA              |
| 00500                | USER READ/WRITE MEMORY      |
| F4000                | CASETTE BASIC INTERPRETER   |
| FE000                | BIOS PROGRAM AREA           |

It's interesting that location 0x7c00 falls in a large section with a fairly generic description. It isn't clearly defined or called out as a "boot sector" area, [as it often is in modern documentation](https://wiki.osdev.org/Memory_Map_(x86)#Overview). We'll need to keep looking for references to boot behaviors.

Appendix A provides the table of interrupts, their human-readable names, and the location in the BIOS code itself where its behavior is defined. INT 19H is first provided in the BIOS interrupt table on page 3-3 (page 167 in the PDF):

| Interrupt Number | Name      | BIOS Initialization    |
| ---------------- | --------- | ---------------------- |
| 19               | Bootstrap | BOOT_STRAP (F000:E6F2) |

This confirms that INT 19H plays a role in the boot code, and that we can find more information in address E6F2. Fortunately, the manual also gives us a complete assembly listing, so let's find the [INT 19H definition](https://gist.github.com/halcyondream/93726fe6877a6f48ee50c417f38740a3).

This is located in Appendix A, page A-20 (page 210 in the PDF), on line 1355, the block comment which precedes offset E6F2:

```
;--- INT 19 -----------------------
;BOOT STRAP LOADER
;       IF A 5 1/4" DISKETTE IS AVAILABLE
;       ON THE SYSTEM, TRACK 0, SECTOR 1 IS READ INTO THE
;       BOOT LOCATION (SEGMENT 0, OFFSET 7C00)
;       AND CONTROL IS TRANSFERRED THERE.
...
```

The block comment clearly names the target behavior: if all goes well, dump the boot code into 0x7c00 and transfer execution there.

The `PROC NEAR` and `ENDP` should stand out as Microsoft Assembly (MASM):

```
;--- INT 19 -----------------------
;BOOT STRAP LOADER
;       ...
;----------------------------------
        ASSUME CS:CODE,DS:DATA 
BOOT_STRAP PROC NEAR
        ...
BOOT_STRAP ENDP
```

One convenient side-effect of MASM is that it gives us a clear start and end for this procedure.

The full-line comments in the procedure body shed some light on the algorithm:

1. Load system from diskette.
2. Handle error (unable to IPL from diskette).
3. IPL was successful.

The final command of the procedure occurs right after the third comment, and is the only execution path for success:

```
        JMP     BOOT_LOCN
```

So, execution will transfer to the address at `BOOT_LOCN`. What address is this? The block quote from earlier gave it away, but there's another way we can verify this behavior.

As luck would have it, the guide also shows the assembled bytes represented by each assembly instruction. The location of `BOOT_LOCN` can be inferred from the byte sequence, `EA007C000000`, at the beginning of the line. We can expand this for readability:

```
EA 00 7C 00 00 00
```

You can disassemble this to a similar result as before:

```
$ echo -ne "\xEA\x00\x7C\x00\x00\x00" > realmode.bin
                                                                                
$ hexdump -C realmode.bin                  
00000000  ea 00 7c 00 00 00                                 |..|...|
00000006
                                                                                
$ objdump -D -b binary -mi386 -Maddr16,data16,intel realmode.bin

realmode.bin:     file format binary


Disassembly of section .data:

00000000 <.data>:
   0:	ea 00 7c 00 00       	jmp    0x0:0x7c00
	...
```

This is a far jump to location `0000:7c00`.

