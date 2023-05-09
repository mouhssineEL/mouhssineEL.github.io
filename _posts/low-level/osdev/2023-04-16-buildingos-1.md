---
title: OSDev | Chapter 1 | Freestanding Rust
author: x4sh3s
date: 2023-04-16
categories: [LowLevel, OSDev]
tags: [lowlevel, osdev]
permalink: /lowlevel/osdev/chapter-1
---

## Introduction

The kernel will be written in Rust, which is why we need to do some preparations before starting to code. This will not be the beginning of development, but rather the setup phase. The kernel must be in a file without any links or syscalls. In the previous chapter, programming simple ASM code did not link to any library, but Rust programming (or any language) will do so automatically.

We need to load all necessary functions inside the compiled binary instead of calling them. This will significantly increase the size, but that is not a problem at the moment. Initially, this will decrease our range of functions since we can't access any threads, files, heap, network, random numbers, or I/O.

This type of executable is called *freestanding* or *bare-metal*.

<br>

---

## The Standard Library

Firstly, we must disable the **Standard Library** (`std`)[^footnote]. As described by the Rust Foundation:

To initiate a Rust project, we can create the basic structure using the following command:
```shell
cargo new zeros
```

To disable `std`, we must edit `main.rs`{: .filepath} and add the `no_std` attribute:
```rust
#![no_std]

fn main() {
    println!("Hello, world!");
}
```
{: file='src/main.rs'}

<br>

---

## The Panic Handler

But we have run into an error:
```
error: cannot find macro `println` in this scope
 --> src/main.rs:4:5
  |
4 |     println!("Hello, world!");
  |     ^^^^^^^
```
{: file='Error'}

As we previously stated, we don't have access to any built-in functions. Removing `println!` does not eliminate the errors.
```
error: `#[panic_handler]` function required, but not found
error: language item required, but not found: `eh_personality`
```
{: file='Error'}

We must first set up a panic function. While `std` provides its own panic functions, we now need to build our own:
```rust
use core::panic::PanicInfo;

// Panic handler
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
```

<br>

---

## The eh_personality

Rust uses [unwinding](/lowlevel/buildingos/chapter-0#stack-unwinding) of all stack variables in case of *panic*. However, unwinding requires some OS-specific libraries (such as *libunwind*) that we don't currently have. To disable it in `Cargo.toml`{: .filepath}, we can make the following change, which will cause the program to abort in case of a panic:
```rust
[profile.dev]
panic = "abort"

[profile.release]
panic = "abort"
```
{: file='Cargo.toml'}

<br>

---

## The start function

The program encountered a new error:
```
error: requires `start` lang_item
```
{: file='Error'}

Before the `main` function is executed, there is a `start` function that works with the *runtime system*[^fn-nth-2]. According to Wikipedia, a runtime system is:

In a typical Rust binary, execution starts in a C runtime library called `crt0` (*C runtime zero*). The entry point of the Rust runtime is then called from this runtime and is marked as `start`. To overwrite this entry point, we must create our own `_start` function, since we don't have a `main` function:
```rust
#![no_main]

#[no_mangle]
pub extern "C" fn _start() -> ! {
    loop {}
}
```

The use of `no_mangle` disables *name mangling*, which ensures that Rust doesn't rename the function `_start` to another name. We also specify `extern "C"` to ensure that the compiler uses the *C calling convention*.

<br>

---

## Linker Error

The following error appears:
```
error: linking with `cc` failed: exit status: 1
```
{: file='Error'}

> This is a Linux Linker error
{: .prompt-info}

The linker is a program that combines the generated code into an executable. Each system has its own linker. In this case, the error is caused by the program thinking that it depends on the C runtime. We need to specify that the linker should not include the C runtime.

The next step is to specify that we don't want to build for a target OS, but instead create our own.

<br>

---

## References

- [Freestanding Rust Binary](https://os.phil-opp.com/freestanding-rust-binary/)
- [Crate std](https://doc.rust-lang.org/std/index.html)

<br>

---

## Footnotes

[^footnote]: The Rust Standard Library is the foundation of portable Rust software, providing a set of minimal and battle-tested shared abstractions for the broader Rust ecosystem.
[^fn-nth-2]: In computer programming, a runtime system or runtime environment is a sub-system that exists both in the computer where a program is created, as well as in the computers where the program is intended to be run.
