---
layout: post
title: Troubleshooting buffer overflows in your vulnerable 32-bit binary
date: 2023-09-19
---

This writeup will cover GCC's stack alignment features and how they can interfere with testing a simple 32-bit buffer overflow. GCC implement's stack alignment by using two LEA instructions, the second of which will change the value of your payload. 

As a workaround, you can either manipulate a byte to account for this offset. For simple tests, you can also just disable stack alignment.

# Background

This writeup was inspired after watching [this Live Overflow video](https://www.youtube.com/watch?v=HSlhY4Uy8SA). It's a great walkthrough for a basic shellcode methodology. However, the prebuilt binary doesn't have GCC stack alignment enabled, as evident in the disassembly at 1:40.

If you take the same C code at the 0:30 mark, and build it yourself in Debian, you won't get the same results as-is. You'll have to modify the payload or the build. We will use that code verbatim in this walkthrough and illustrate what changes in the assembly.

# Problem

Suppose you want to exploit a simple buffer overflow. Let's start with some vulnerable code:

```c
#include <stdio.h>

int main() {
  char buffer[4];
  gets(buffer);
}
```

Save it in a file called *bof.c*.

The *gets* function is well-known and insecure. In fact, the compiler will yell at you just for trying to use it. 

```
$ gcc bof.c -o bof.out                                  
bof.c: In function ‘main’:
bof.c:5:3: warning: implicit declaration of function ‘gets’; did you mean ‘fgets’? [-Wimplicit-function-declaration]
    5 |   gets(buf);
      |   ^~~~
      |   fgets
/usr/bin/ld: /tmp/ccj0LXg4.o: in function `main':
bof.c:(.text+0x15): warning: the `gets' function is dangerous and should not be used.
```

Its use here is simple: to overwrite the buffer, a behavior you should *never* allow outside of an intentionally vulnerable proof-of-concept.

On x86_64 and ARM64, you can build and test the code pretty simply:

```
gcc bof.c -o bof.out -fno-stack-protector
```

Ignore the yelling about *gets*. 

We want to relax any stack protections in order to pull off the overflow. (Note: I've had mixed results with whether the `-fno-stack-protector` option will inhibit an overflow. I'm keeping it because it's a well-known practice to enable it for this kind of exercise.)

For the payload, we can keep it simple. 

```
AAAABBBBCCCCDDDDEEEEFFFF
```

On a 64-bit system, we expect that eight of these letters, in pairs of four bytes, will appear in the stack.

In GDB, you can run the attack:

```
$ gdb bof.out                              
GNU gdb (Debian 13.2-1) 13.2
...
(gdb) r
Starting program: /home/kali/bof.out 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
AAAABBBBCCCCDDDDEEEEFFFF

Program received signal SIGSEGV, Segmentation fault.
0x4545454544444444 in ?? ()
(gdb) i r rip
rip            0x4545454544444444  0x4545454544444444
```

Based on the output, the application tried to execute *0x4545454544444444*. This is the little-endian representation of *DDDDEEEE*, a section from our simple payload. So, the overflow attack was successful.

However, let's try the same thing for a 32-bit build.

```
gcc bof.c -o bof.out -m32 -march=i386 -fno-stack-protector
```

(Note: You may need to install other dependencies to cross-compile. On Debian systems, you can install the  `gcc-multilib` package.)

Open it in GDB and run the same commands.

```
$ gdb bof.out 
GNU gdb (Debian 13.2-1) 13.2
...
(gdb) r
Starting program: /home/kali/bof.out 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
AAAABBBBCCCCDDDDEEEEFFFF

Program received signal SIGSEGV, Segmentation fault.
0x565561c8 in main ()
(gdb) i r eip
eip            0x565561c8          0x565561c8 <main+59>
(gdb) i r esp
esp            0x4242423e          0x4242423e
```

The application tried to access *0x4242423e*. Notice that this almost matches the *BBBB* input from our payload. However, one byte is off. Why?

At this point, you could try different payloads, and you'll notice the off-by-negative-four each time. This is part of how GCC implements stack alignment. The reason why this happens is evident in the disassembly. 

# GCC Stack Alignment

Disassemble the application logic:

```
(gdb) disassemble main
Dump of assembler code for function main:
   0x5655618d <+0>:	lea    ecx,[esp+0x4]
   0x56556191 <+4>:	and    esp,0xfffffff0
   0x56556194 <+7>:	push   DWORD PTR [ecx-0x4]
   0x56556197 <+10>:	push   ebp
   0x56556198 <+11>:	mov    ebp,esp
   0x5655619a <+13>:	push   ebx
   0x5655619b <+14>:	push   ecx
   0x5655619c <+15>:	sub    esp,0x10
   0x5655619f <+18>:	call   0x565561c9 <__x86.get_pc_thunk.ax>
   0x565561a4 <+23>:	add    eax,0x2e50
   0x565561a9 <+28>:	sub    esp,0xc
   0x565561ac <+31>:	lea    edx,[ebp-0xc]
   0x565561af <+34>:	push   edx
   0x565561b0 <+35>:	mov    ebx,eax
   0x565561b2 <+37>:	call   0x56556040 <gets@plt>
   0x565561b7 <+42>:	add    esp,0x10
   0x565561ba <+45>:	mov    eax,0x0
   0x565561bf <+50>:	lea    esp,[ebp-0x8]
   0x565561c2 <+53>:	pop    ecx
   0x565561c3 <+54>:	pop    ebx
   0x565561c4 <+55>:	pop    ebp
   0x565561c5 <+56>:	lea    esp,[ecx-0x4]
   0x565561c8 <+59>:	ret
End of assembler dump.
```

Observe the LEA instruction at *0x565561c5* (*main*+56):

```
lea    esp,[ecx-0x4]
```

In short, this instruction is saying that the value in *ECX* will be subtracted by 4, then set as the address of *ESP*. Let's rerun and see what's in *ECX* before and after that instruction:

```
(gdb) b *(main+56)
Breakpoint 1 at 0x565561c5
(gdb) r
...
Breakpoint 1, 0x565561c5 in main ()
=> 0x565561c5 <main+56>:	lea    esp,[ecx-0x4]
(gdb) i r esp
esp            0xffffd48c          0xffffd48c
(gdb) i r ecx
ecx            0x42424242          1111638594
(gdb) ni
0x565561c8 in main ()
(gdb) x/1i $pc
=> 0x565561c8 <main+59>:	ret
(gdb) i r esp
esp            0x4242423e          0x4242423e
(gdb) i r ecx
ecx            0x42424242          1111638594
```

So, *ESP* is set to *0x42424242 - 0x4*, or *0x4242423e*. All because of that LEA instruction. Go back a bit in the disassembly and observe a similar instruction at the beginning of *main*:

```
   0x5655618d <+0>:	lea    ecx,[esp+0x4]
```

What are the LEA instructions doing?

This is actually a compiler optimization: enforcing a 16-byte stack boundary. There are valid, beneficial reasons why GCC adds this. You can read more about this elsewhere, but the gist is that, if GCC fails to account for this, an application may experience undefined behavior.

Notice that, in the 64-bit build, these instructions do not appear at all. Rebuild the 64-bit version as we did earlier, then view the disassembly:

```
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000001139 <+0>:   push   rbp
   0x000000000000113a <+1>:   mov    rbp,rsp
   0x000000000000113d <+4>:   sub    rsp,0x10
   0x0000000000001141 <+8>:   lea    rax,[rbp-0x4]
   0x0000000000001145 <+12>:  mov    rdi,rax
   0x0000000000001148 <+15>:  mov   eax,0x0
   0x000000000000114d <+20>:  call   0x1030 <gets@plt>
   0x0000000000001152 <+25>:  mov   eax,0x0
   0x0000000000001157 <+30>:  leave
   0x0000000000001158 <+31>:  ret
```

However, for the purpose of testing a 32-bit binary, it also means that one byte of our overflow will be off by 4. This makes it harder to test well-documented vulnerable C examples and walkthroughs that target 32-bit systems. Further, if something like a CTF builds a 32-bit binary with this feature, it also means that you may need to compensate in your payload.

Here are two fairly simple workarounds. They have not been *rigorously* tested, but they should do the job if you're in a pinch.

# Workaround 1: Basic Addition

With all other factors aside, a really simple compensating technique is just to add 4 to the value of whatever payload you intend to send, for the "last" (Little Endian) byte. So, if we wanted to overflow ESP wih *AAAA*, we could send:

```
BBBBEAAA
```

The first four bytes are just padding. The next four bytes will overflow and resolve to *AAAA*. Since *E = 0x45*, this will become to *0x41 = A* after the final LEA instruction in *main*.

Check it in the debugger:

```
(gdb) disas main
Dump of assembler code for function main:
   ...
   0x565561c5 <+56>:	lea    esp,[ecx-0x4]
   0x565561c8 <+59>:	ret
End of assembler dump.
(gdb) r
...
BBBBEAAA
Program received signal SIGSEGV, Segmentation fault.
0x565561c8 in main ()
(gdb) i r esp
esp            0x41414141          0x41414141
```

Since *ESP = 0x41414141*, the intended payload is the overflow value.

Although this is a trivial payload, the approach may be useful if you need to send, for example, shellcode or a target address. This approach is probably best for cases where you need to target a prebuilt binary and can observe these additional instructions. In other cases, you can also use GCC flags to fine-tune the stack alignment.

# Workaround 2: GCC flags

If you're trying to follow an existing walkthrough that does not have these stack-aligning features enabled, and you just want to follow the walkthrough verbatim, you can also disable the features with `-mpreferred-stack-boundary=2`, like:

```
gcc bof.c -o bof.out -m32 -march=i386 -fno-stack-protector -mpreferred-stack-boundary=2
```

The resultant disassembly should no longer have the LEA instructions:

```
(gdb) disas main
Dump of assembler code for function main:
   0x0000118d <+0>:	push   ebp
   0x0000118e <+1>:	mov    ebp,esp
   0x00001190 <+3>:	push   ebx
   0x00001191 <+4>:	sub    esp,0x4
   0x00001194 <+7>:	call   0x11b6 <__x86.get_pc_thunk.ax>
   0x00001199 <+12>:	add    eax,0x2e5b
   0x0000119e <+17>:	lea    edx,[ebp-0x8]
   0x000011a1 <+20>:	push   edx
   0x000011a2 <+21>:	mov    ebx,eax
   0x000011a4 <+23>:	call   0x1040 <gets@plt>
   0x000011a9 <+28>:	add    esp,0x4
   0x000011ac <+31>:	mov    eax,0x0
   0x000011b1 <+36>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x000011b4 <+39>:	leave
   0x000011b5 <+40>:	ret
```

Test it with GDB:

```
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/kali/bof.out 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
AAAABBBBCCCCDDDDEEEEFFFF

Program received signal SIGSEGV, Segmentation fault.
0x44444444 in ?? ()
```

So, we were able to deliver the payload as-is, without accounting for any four-byte offset.

This is probably best for cases where the vulnerable code is fairly "simple" (few custom function calls) and where you're following someone else's walkthrough. Should you encounter undefined behavior due to the stack alignment, you will need to put in some elbow grease: either offsetting your payloads by 4, or fine-tuning the stack-alignment flags after some research.