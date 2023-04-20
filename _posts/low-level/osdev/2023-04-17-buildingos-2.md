---
title: OSDev | Chapter 2 | Rust Kernel
author: Zeropio
date: 2023-04-17
categories: [LowLevel, OSDev]
tags: [lowlevel, osdev]
permalink: /lowlevel/osdev/chapter-2
---

# Introduction

Now that we have a freestanding Rust binary, the next step is to create the kernel. We will create a 64-bit kernel for the x86 architecture. As we saw in the first chapter, we will begin by developing a bootable file.

<br>

---

# The Boot

As explained in [Chapter 0](/lowlevel/buildingos/chapter-0#booting), almost all modern machines have a BIOS. When a computer is started, the BIOS runs by itself and initializes all the hardware. It then looks for disks and searches for a bootable section. This *bootloader* must be a 512-byte section. Additionally, we need to switch from 16-bit *real mode* to 32-bit *protected mode* (as we did in [Chapter 0](/lowlevel/buildingos/chapter-0#protected-mode)) and then to 64-bit *long mode*.

Instead of crafting the bootloader in ASM as we did before, we will use the [bootimage](https://crates.io/crates/bootimage) crate.

<br>

---

# Creating the Architecture

As we have seen, by default, Rust compiles to a target OS and architecture. To write a kernel, we must specify that we don't want to compile to an OS, but rather be the OS itself. During compile time, we can use the `--target` flag to select this or we can build our own JSON file:
```json
{
    "llvm-target": "x86_64-unknown-none",
    "data-layout": "e-m:e-i64:64-f80:128-n8:16:32:64-S128",
    "arch": "x86_64",
    "target-endian": "little",
    "target-pointer-width": "64",
    "target-c-int-width": "32",
    "os": "none",
    "executables": true,
    "linker-flavor": "ld.lld",
    "linker": "rust-lld",
    "panic-strategy": "abort",
    "disable-redzone": true,
    "features": "-mmx,-sse,+soft-float",
}
```
{: file='x86_64-zeros.json'}

We change the `os` and `llvm-target` to `none`. We also change the linker from the default linker (in this case Linux) to the Rust linker. We set the `panic-strategy` to `abort` to disable *stack unwinding*[^footnote]. We disable the *red zone*[^fn-nth-2]. Finally, we disable `mmx` and `sse` (support for **SIMD**, **S**ingle **I**nstruction **M**ultiple **D**ata, which can speed up programs, but create performance problems in OS kernels) and enable `soft-float`. Because the `x86_64` architecture needs SIMD registers, we need to add `soft-float` to emulate all floating-point operations.

<br>

---

# Compiling the Kernel


If we try to compile the kernel, it will crash because it can't find the `core` library. This library is precompiled for each target Rust has, but since we are using our own target, we don't have it yet.

To fix this, we need to use `build-std` in our `.cargo/config.toml` file. Add this line:
```toml
[unstable]
build-std = ["core", "compiler_builtins"]
```
{: file='.cargo/config.toml'}

To make this work, we need to use Rust nightly:
```
rustup override set nightly
```

Then, we can create a file called `rust-toolchain` with the contents `nightly`. We should see the version:
```
rustc --version
    rustc 1.71.0-nightly (d0f204e4d 2023-04-16)
```

And install:
```
rustup component add rust-src
```

## C Functions

In the future, we will need some C functions such as `memset`, `memcmp`, etc. Since these are from C and we don't have them in the system, we can either build our own functions (which could lead to errors) or enable the compilation of the C library to the system. Before the `build-std` section in `.cargo/config.toml`, add:
```toml
build-std-features = ["compiler-builtins-mem"]
```
{: file='.cargo/config.toml'}

## Default Target

To avoid specifying the kernel target each time we compile, we can set the default target in `.cargo/config.toml`:
```toml
[build]
target = "x86_64-zeros.json"
```
{: file='.cargo/config.toml'}

<br>

---

# Printing some String

To output some text in the system, for a health check, we can print a string on the *VGA text buffer*[^fn-nth-3]. For this, we need to:

- Create a string:
```rust
static HELLO: &[u8] = b"Hello World";
```

- Then, in our `_start` function, convert the integer `0xb8000` to a raw pointer:
```rust
let vga_buffer = 0xb8000 as *mut u8;
```

- Iterate over the string:
```rust
for (i, &byte) in HELLO.iter().enumerate() {
    unsafe {
        *vga_buffer.offset(i as isize * 2) = byte;
        *vga_buffer.offset(i as isize * 2 + 1) = 0x4;
    }
```

The `enumerate` method gets the running variable `i`. The `offset` method writes the string byte with the color red (`0x4`). The `unsafe` usage allows us to interact directly with the OS. In this case, we can call raw pointers without having an error. The final version is:
```rust
static HELLO: &[u8] = b"Hello World from ZerOS!";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let vga_buffer = 0xb8000 as *mut u8;

    for (i, &byte) in HELLO.iter().enumerate() {
        unsafe {
            *vga_buffer.offset(i as isize * 2) = byte;
            *vga_buffer.offset(i as isize * 2 + 1) = 0x4;
        }
    }

    loop {}
}
```

<br>

---

# Running the Kernel

First, we need to add the `bootimage` dependency to `Cargo.toml`:
```toml
[dependencies]
bootloader = "0.9.23"
```
{: file='Cargo.toml'}

> Newer versions may crash!
{: .prompt-danger}

Install the necessary dependencies:
```shell
cargo install bootimage
rustup component add llvm-tools-preview
```

Now we can compile it with:
```shell
cargo bootimage
```

We need to use `bootimage` because Rust doesn't directly compile to a `.iso` or `.bin`, so we cannot boot from it. The `bootimage` tool helps us make it a bootable file. We can easily execute it by running:
```shell
qemu-system-x86_64 target/x86_64-zeros/debug/bootimage-zeros.bin
```

Our kernel is now up and running:
![](/assets/img/osdev/2023-04-17_16-25.png)
_Running Kernel_

With this, we have achieved the same functionality as in Chapter 0, but using Rust instead of Assembly.

<br>

---

# More Text

We'll be using Rust's [Macros](https://veykril.github.io/tlborm/) functionality to create a more stable method for printing to VGA. To print to the VGA buffer, we must write to it in a specific format:

| **Bits** | **Value** | 
| -------- | --------- |
| 0 - 7 | ASCII |
| 8 - 11 | Foreground color |
| 12 - 14 | Background color |
| 15 | Blink |

| **Value** | **Color** | **Value** | **Color** |
| --------- | --------- | --------- | --------- |
| 0x0 | Black | 0x8 | Dark Gray |
| 0x1 | Blue | 0x9| Light Blue |
| 0x2 | Green | 0xa | Light Green |
| 0x3 | Cyan | 0xb | Light Cyan |
| 0x4 | Red | 0xc | Light Red |
| 0x5 | Magenta | 0xd | Pink |
| 0x6 | Brown | 0xe | Yellow |
| 0x7 | Light Gray | 0xf | White |

The VGA buffer is a memory-mapped I/O located at address `0xb8000`. While the text buffer supports normal reads and writes, some memory-mapped I/O does not support all RAM operations. Therefore, we need to implement a writer that only writes to the buffer. It's important to note that the compiler doesn't differentiate between the VGA buffer memory and normal RAM, so it may not recognize the characters we're attempting to print, resulting in errors.

To address this issue, we'll add the macro to `vga_buffer.rs`.

## Colors

First, we'll create an enum that includes all the colors. We'll use a *C-like enum* to add a `u8` value. The `#[allow(dead_code)]` attribute disables warnings for unused variants:
```rust
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    Pink = 13,
    Yellow = 14,
    White = 15,
}
```
{: .file='src/vga_buffer.rs'}

To represent colors, we'll create a struct that sets both foreground and background colors, and we'll use the *derive* macro to include the `Debug`, `Clone`, `Copy`, `PartialEq`, and `Eq` traits. We'll also use the `repr(transparent)` attribute to ensure the struct has the same data layout as `u8`:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct ColorCode(u8);

impl ColorCode {
    fn new(foreground: Color, background: Color) -> ColorCode {
        ColorCode((background as u8) << 4 | (foreground as u8))
    }
}
```
{: .file='src/vga_buffer.rs'}

## Text and Volatile

The issue with the code is that it only writes to `Buffer` and never reads from it again. Since the compiler doesn't know which characters are being printed, some may be omitted. To prevent these errors, we'll use the [volatile](https://docs.rs/volatile/latest/volatile/) crate. This creates a `Volatile` wrapper with `read` and `write` methods. First, we'll need to add the dependency:
```rust
[dependencies]
volatile = "0.2.6"
```
{: .file='Cargo.toml'}

To represent a character on the screen, we need to use `repr(C)` to implement a C struct and guarantee the field ordering. For the `Buffer`, we'll use `repr(transparent)` again:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct ScreenChar {
    ascii_character: u8,
    color_code: ColorCode,
}

const BUFFER_HEIGHT: usize = 25;
const BUFFER_WIDTH: usize = 80;

#[repr(transparent)]
struct Buffer {
    chars: [[Volatile<ScreenChar>; BUFFER_WIDTH]; BUFFER_HEIGHT],
}
```
{: .file='src/vga_buffer.rs'}

To write on the screen, we'll create a type. We'll need to use a *lifetime* to indicate to the compiler how long the reference is valid. In this case, `'static` specifies that the reference is valid for the entire runtime:
```rust
pub struct Writer {
    column_position: usize,
    color_code: ColorCode,
    buffer: &'static mut Buffer,
}
```
{: .file='src/vga_buffer.rs'}

## Printing

We'll implement some functions to `Writer` to enable writing:

- `write_byte`: This writes a single ASCII byte. If the byte is `\n`, it calls the `new_line` method. Since we're using the `Volatile` wrapper, we need to use the `write` method.
```rust
pub fn write_byte(&mut self, byte: u8) {
    match byte {
        b'\n' => self.new_line(),
        byte => {
            if self.column_position >= BUFFER_WIDTH {
                self.new_line();
            }

            let row = BUFFER_HEIGHT - 1;
            let col = self.column_position;

            let color_code = self.color_code;
            self.buffer.chars[row][col].write(ScreenChar {
                ascii_character: byte,
                color_code,
            });
            self.column_position += 1;
        }
    }
}
```

- `write_string`: To print a whole string, we convert it to bytes and print them one-by-one. For unprintable bytes, we print the `0xfe` character.
```rust
fn write_string(&mut self, s: &str) {
    for byte in s.bytes() {
        match byte {
            0x20..=0x7e | b'\n' => self.write_byte(byte),
            _ => self.write_byte(0xfe),
        }
    }
}
```

- `new_line`: This moves all the characters one row up.
```rust
fn new_line(&mut self) {
    for row in 1..BUFFER_HEIGHT {
        for col in 0..BUFFER_WIDTH {
            let character = self.buffer.chars[row][col].read();
            self.buffer.chars[row - 1][col].write(character);
        }
    }
    self.clear_row(BUFFER_HEIGHT - 1);
    self.column_position = 0;
}
```

- `clear_row`: This clears a row by overwriting all of its characters with a space character.
```rust
fn clear_row(&mut self, row: usize) {
    let blank = ScreenChar {
        ascii_character: b' ',
        color_code: self.color_code,
    };
    for col in 0..BUFFER_WIDTH {
        self.buffer.chars[row][col].write(blank);
    }
}
```

## Macros

We can implement the `Write` method from `fmt`:
```rust
use core::fmt;

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}
```

## println Macro

Statics are initialized at compile time, unlike other variables. To initialize statics at runtime, we need to use the [lazy_statics](https://crates.io/crates/lazy_static) crate. First, add it. The `spin_no_std` crate allows us not to link to `std`:
```toml
[dependencies.lazy_static]
version = "1.0"
features = ["spin_no_std"]
```
{: .file='Cargo.toml'}

Now we can use `lazy_static!` to define the static `WRITER`. Since all the write methods take `&mut self`, we can't write anything to it. If we use a mutable static, it will be unsafe code because it could easily introduce data races. To get a *synchronized* interior mutability, we can use the [Mutex](https://doc.rust-lang.org/nightly/std/sync/struct.Mutex.html) struct.

We can use a *spinlock*[^fn-nth-4] to create a loop instead of blocking the threads. First, add the dependency:
```toml
[dependencies]
spin = "0.5.2"
```
{: .file='Cargo.toml'}

Now we can create the *unsafe* function to print with interior mutability:
```rust
use spin::Mutex;

lazy_static! {
    pub static ref WRITER: Mutex<Writer> = Mutex::new(Writer {
        column_position: 0,
        color_code: ColorCode::new(Color::Yellow, Color::Black),
        buffer: unsafe { &mut *(0xb8000 as *mut Buffer) },
    });
}
```
{: .file='src/vga_buffer.rs'}

For easier access, we can create the `println` macro. This function has two rules: printing without parameters (simple `println()`) and printing with parameters (`println("Hi")` or `println("{}", 4)`). For this, we can copy the `println!` function from Rust:
```rust
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
```
{: .file='src/vga_buffer.rs'}

We are now able to use the `println` macro to print messages to the screen.
```rust
#[no_mangle]
pub extern "C" fn _start() {
    println!("Hello World{}", "!");

    loop {}
}
```
{: .file='src/main.rs'}

<br>

---

# Final Result

Our Kernel is now operational and printing output to the screen:

![](/assets/img/osdev/2023-04-20_12-50.png)
_Running Kernel_

<br>

---

# References

- [A Minimal Rust Kernel](https://os.phil-opp.com/minimal-rust-kernel/)
- [Unsafe Rust](https://doc.rust-lang.org/stable/book/ch19-01-unsafe-rust.html)
- [VGA Text Mode](https://os.phil-opp.com/vga-text-mode/)
- [Stack Unwinding](https://www.bogotobogo.com/cplusplus/stackunwinding.php)
- [Red Zone](https://eli.thegreenplace.net/2011/09/06/stack-frame-layout-on-x86-64#the-red-zone)

<br>

---

# Footnote

[^footnote]: **Stack unwinding** is the process of *unrolling* the call stack in a computer program when an exception or error occurs. This involves reversing the sequence of function calls that led to the error, deallocating resources that were allocated during those calls, and returning control to the point where the error occurred. The purpose of stack unwinding is to ensure that the program exits gracefully and that all resources are properly cleaned up, even in the event of an unexpected error.
[^fn-nth-2]: The **Red Zone** is an optimization that allow functions the use of the 128 bytes below their stack frame. This optimization leads to problems with exceptions and hardware interrupts. If a function is stopped while using the red zone, and the CPU overwrite it, the function still need the previous values from it. This leads to strange and hard-to-find bugs.
[^fn-nth-3]: It is a special memory area mapped to the VGA hardware, that display the contents on screen. Normally, consist of 25 lines with 80 characters each.
[^fn-nth-4]: is a lock that causes a thread trying to acquire it to simply wait in a loop while repeatedly checking whether the lock is available.