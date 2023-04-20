---
title: OSDev | Chapter 0 | Basic Kernel
author: x4sh3s
date: 2023-04-13
categories: [LowLevel, OSDev]
tags: [lowlevel, osdev]
comments: true
toc: true
permalink: /lowlevel/osdev/chapter-0
---

# Introduction

This series, is a personal project focused on learning more about ASM, kernel development, computer basics, and Rust. This is not a professional blog, and I will be using resources from various sites. Some of the posts may be scripts, while others will not. I will always include a **Resources** section with all the sites I consulted. Please feel free to point out any errors.

Also, I'm going to assume that you already know some stuff. So, I won't be explaining things like what a CPU is or what ASM is, or how to write in ASM from scratch.

If anyone want to replay my practices, I'm doing this on a native Arch Linux with Qemu as hypervisor. Also, I will be mainly following [Writing an OS in Rust](https://os.phil-opp.com/) from Philipp Oppermann.

Enjoy!

<br>

---

# Booting

When a computer starts up, the first thing it does is look for an operating system. This OS is located in a section of the memory called the **boot sector**, which is the first sector of a bootable drive. It is recognizable as it is 512 bytes long and ends with `55 AA`.

A simple bootable can be created using the following code:

```nasm
jmp $

times 510-($-$$) db 0
db 0x55, 0xaa
```

Let's analyze line by line:

```nasm
times 510-($-$$) db 0
```

The `times` repeats a number of times (`510-($-$$)`) an action (`db 0`). In this case, add the byte 0 to the code. The `$$` represent the beginning of the current section, so `$-$$` is the length of the previous code.

Then, add the last bytes to make it a bootable section:

```nasm
db 0x55, 0xaa
```

After creating the code, it can easily be compiled into a *bin* file and booted with QEMU:

```shell
nasm -f bin boot.asm -o boot.bin
qemu-system-x86_64 boot.bin
```

![Untitled](/assets/img/osdev/Untitled.png)
_Simple boot_

<br>

---

# Strings

## Printing

We can use the ********BIOS******** (**B**asic **I**nput/**O**utput **S**ystem) to perform some functions, like printing characters on screen. To print a char in NASM we need to build the following:

```nasm
mov ah, 0x0e ; set ah
mov al,'Z' ; move the character
int 0x10 ; call BIOS interreput
```

But sometimes, we don’t just want to print a single character but an entire string. For this, we can use the `db` instruction, that will set bytes in the memory. The string must end with a null byte (`0`):

```nasm
[org 0x7c00]
mov ah, 0x0e
mov al, [string]
int 0x10

jmp $

string:
    db "Welcome to ZerOS!", 0
```

Here, we reference the memory address of the `string` label to `al`. Memory address doesn’t start by 0 - instead they start with the offset `0x7c00`. The BIOS has its own *Interrupt Vector Table* with all the interrupt codes. They are loaded before any other program, and for safety reasons, the origin is taken at `0x7c00` to avoid collisions.

We can add it to the reference (`[string + 0x7c00]`) or set the origin at that address (`[org 0x7c00]`).

This only prints the first character. We can start a small program to print the whole string:

```nasm
[org 0x7c00]
mov ah, 0x0e
mov bx, string

print:
    mov al, [bx]
    cmp al, 0
    je end
    int 0x10
    inc bx
    jmp print
end:

jmp $

string:
    db "Welcome to ZerOS!", 0

times 510-($-$$) db 0
db 0x55, 0xaa
```

Now we can print anything!

![Untitled](/assets/img/osdev/Untitled%201.png)
_String Print_

## Input

Now we need to input some data, instead of just printing. We have the BIOS interreput `0x16` with `ah = 0`. Here, we have implemented a buffer that allocates a string of 10 bytes:

```nasm
buffer:
    times 10 db 0
    mov bx, buffer
    mov [bx], al
    inc bx
    cmp bx,
mov ah, 0
int 0x16

mov al, [char]
```

<br>

---

# Reading Disk

All BIOS count with functions to read from it. HHD disk has **C**ylinders where the data is stored, and two **H**ead for each - one for read and one for write. Also, each platter is divided into **S**ectors, with each sector being divided into 512 bytes (like the boot sector).

![](/assets/img/osdev/Section-1.png)

When the BIOS read the disk, it needs to know **CHS**. We can modify the code to add a full section:

```nasm
[org ox7c00]
jmp $
times 510-($-$$) db 0
db 0x55, 0xaa
times 512 db 'A'
```

The call `int 0x13` for read the disk need the following:

- What disk to read
- CHS address (**C** and **H** start by 0, while **S** start by 1)
- How many sectors?
- Where do we load them?

We can use the following code:

```nasm
mov ah, 2
mov al, 1   ; number of sectors
mov ch, 0   ; cylinder number
mov cl, 2   ; sector number
mov dh, 0   ; head number
mov dl, [disk]    ; driver number, saved in a variable
int 0x13
```

Now, we can print a value from the disk:

```nasm
mov ah, 0x0e
mov al,[0x7e00]
int 0x10
```

To create the disk, just:

```nasm
mov [disk], dl
...
disk: db 0
```

And set up the stack:

```nasm
xor ax, ax
mov es, ax
mov ds, ax
mov bp, 0x8000
mov sp, bp

mov bx, 0x7e00
```

The final code will be:

```nasm
[org 0x7c00]
mov [disk], dl

; setting up the stack
xor ax, ax
mov es, ax
mov ds, ax
mov bp, 0x8000
mov sp, bp

mov bx, 0x7e00

; reading the disk
mov ah, 2
mov al, 1
mov ch, 0
mov dh, 0
mov cl, 2
mov dl, [disk]
int 0x13

; printing the first sector
mov ah, 0x0e
mov al, [0x7e00]
int 0x10
jmp $
disk: db 0

times 510-($-$$) db 0
dw 0xaa55

times 512 db 'A'
```

<br>

---

# Protected Mode

**Protected Mode** is a 32 bits operational mode. First, we need to start segmentation in **PM**. For this we will not use registers, but the **GDT** (**G**lobal **D**escriptor **T**able).

## Descriptors

We need to find a **Descriptors** (a list of properties of a segment) for each segment we are going to use in PM. There are several memory models and technique, as:

- Flat memory model: use memory address as a single continous space
- Segmentarion
- Paging

GDT must contain a **code segment Descriptor** and **data segment Descriptor**.

### Code Segment Descriptor

First, we need to define the size of the segment and the location. The **base** property of the segment describes the starting location, and **limit** describes the size.

Then we have:

- **Present** - single bit, set to `1` if the segment is used
- **Privilege** - two bit value from zero to three, used to define *segment hierarchy* and *memory protection*, the highest privilege is `00` (*ring*)
- **Type** - single bit, set to `1` if it is code segment

The others propertiers are **flags**. We have **Type flags** (4 bits):

- Code - if it is code it’s value is `1`
- Conforming - if the code can be executed from lower privileged segments (`0` for no)
- Readable -  if it is readable the value is `1`
- Accessed - managed by CPU, set to `0` to let the CPU work

The **Other flags** (4 bits):

- Granualarity - when it is `1` the limit is multiply by `0x1000`, so we can span 4GB of memory
- 32 bits - `1` for years
- the other two must be set to `0`

So the end view will be:

| pres,priv,type | 1001 |
| --- | --- |
| Type flags | 1010 |
| Other flags | 1100 |

### Data Segment Descriptor

We should change the following:

- No code flag
- Conforming get repace by direction, if it is `1` the segment become a *expand down segment* (grows downwards)
- Readable change to writeable

So the end view will be:

| pres,priv,type | 1001 |
| --- | --- |
| Type flags | 0010 |
| Other flags | 1100 |

## Define GDT in ASM

We need to define:

- `db` - define bytes
- `dw` - defines words
- `dd` - defines double words

First we need to define a **null** descriptor, then the **code** and the **data** descriptors, ended by `GDT_end`:

```nasm
GDT_Start:
    GDT_null:
        dd 0x0
        dd 0x0

    GDT_code:
        dw 0xffff        ; define 16 firsts bits of the limit
        dw 0x0
        db 0x0           ; define 24 first bits of the base
        db 0b10011010    ; define present, privilege and type properties and type flags
        db 0b11001111    ; define other flags and last four bits of the limit
        db 0x0           ; last 8 bits

    GDT_data:
        dw 0xffff
        dw 0x0
        db 0x0
        db 0b10010010
        db 0b11001111
        db 0x0
```

Now we need to describe a `GDT_Descriptor`:

```nasm
GDT_descriptor:
    dw GDT_end - GDT_start - 1 ; size
    dd GDT_start               ; start
```

To use that values we need to declare them previously:

```nasm
CODE_SEG equ GDT_code - GDT_start
DATA_SEG equ GDT_data - GDT_start
```

Now we can switch to **Protected Mode**. First, disable all interrupts using `cli`. Then load GDT using the `lgdt`. Then, we need to change the last bit of a special 32-bit register called `cr0` to `1`. Since we cannot change it directly, we need to use a 32 bit register for it.

```nasm
cli
lgdt [GDT_Descriptor]

; change last bif of cr0 to 1
mov eax, cr0
or eax,1
mov cr0,eax
```

Now, the CPU is in PM 32-bits. Now we need to do a **far jump** to another segment or label. For example:

```nasm
[bits 32]
start_protected_mode:
```

We must define the bits (`[bits 32]`). Now we can’t use BIOS, now we need to write to **Video Memory** directly, which in text mode starts by `0xb8000`. The first byte will be the character, while the second the colour:

```nasm
[bits 32]
start_protected_mode:
mov al,'A'
mov ah,0x0f ; white on black
mov [0xb8000], ax
```

<br>

---

# Final Code

```nasm
[org 0x7c00]

CODE_SEG equ GDT_code - GDT_start
DATA_SEG equ GDT_data - GDT_start

cli
lgdt [GDT_descriptor]
mov eax, cr0
or eax, 1
mov cr0, eax
jmp CODE_SEG:start_protected_mode

jmp $

GDT_start:
    GDT_null:
        dd 0x0
        dd 0x0

    GDT_code:
        dw 0xffff
        dw 0x0
        db 0x0
        db 0b10011010
        db 0b11001111
        db 0x0

    GDT_data:
        dw 0xffff
        dw 0x0
        db 0x0
        db 0b10010010
        db 0b11001111
        db 0x0

GDT_end:

GDT_descriptor:
    dw GDT_end - GDT_start - 1
    dd GDT_start

[bits 32]
start_protected_mode:
    mov al, 'A'
    mov ah, 0x0f
    mov [0xb8000], ax
    jmp $

times 510-($-$$) db 0
dw 0xaa55
```

And now, we can write anything:

![Untitled](/assets/img/osdev/Untitled%203.png)
_Final Version_

<br>

---

# References

- [Making an OS (x86)](https://www.youtube.com/playlist?list=PLm3B56ql_akNcvH8vvJRYOc7TbYhRs19M)
- [Wiki OSDev](https://wiki.osdev.org/Main_Page)
- [OS Dever](http://www.osdever.net/)

