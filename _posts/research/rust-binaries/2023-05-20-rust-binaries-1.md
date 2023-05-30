---
title: Reversing Rust 1 | Research
author: x4sh3s
date: 2023-05-20
categories: [research, rustversing]
tags: [research, reversing]
permalink: /research/rustversing/part-1
image: /assets/img/thumbnails/rustversing-1.png
---

Why? you may ask. I had asked myself the same question, but a friend provided me with a different perspective. In the early days of reversing, back in the 80s (I guess?), people didn't know how to reverse a simple C binary like we do today. They started by examining plain disassembly, gradually progressing to where we are now. But what about Rust? It is often said that reversing Rust is far from being stable. Personally, I have noticed a significant lack of blog posts discussing reversing in this language.

This won't be your typical blog praising the merits of Rust and why you should use it. On the contrary, my goal is the opposite. I want to explore the process of reversing Rust binaries and compare them to C binaries. I aim to understand the patterns used by the Rust compiler and improve my skills in reversing Rust binaries.
So, instead of a series praising the virtues of Rust, this will focus on how we can dismantle one of its (today's) strong features—its natural obfuscation.

In future posts, I will attempt to reverse-engineer some malware written in Rust (either my own or using existing "*in the wild*" Rust malware) and develop tools that can aid us in reversing it.

Get ready, Rustaceans! 😈

> Don't take anything seriously!

<br>

---

## Introduction

First things first, what am I going to do?

I will engage in simple Rust programming paired with some C examples. I will cover everything from a basic "*Hello World*" program to binary exploitation. As mentioned in previous posts, I won't dive into the absolute basics. While I'm not a professional, I believe it's more valuable for me to focus on what I'm doing and why, rather than explaining fundamental concepts that others can explain better than I can.

Rest assured, I will do my best. I promise.

<br>

---

## Hello Rust! Hello C!

Let's start with something simple: some "*Hello, World!*" programs.

```rust
fn main() {
    hello();
}

fn hello() {
    let language = "Rust";
    println!("Hello from {}!", language);
}
```

```c
#include <stdio.h>

int main() {
    hello();
}

int hello() {
    char* language = "C";
    printf("Hello from %s!\n", language);
}
```

The first and most obvious difference is the file size. While the C binary has a size of **15 KB**, the Rust binary is **3.9 MB**.

> Both were compiled using the default options for `gcc` and `rustc`.

<br>

### Compilation Checks

Now let's dive into the compilation details:
```console
$ file rust
rust: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a9f161505a45966c69dfda1dc9d3fa3a110c56f7,
for GNU/Linux 4.4.0, with debug_info, not stripped
```
{: file='Rust'}

```console
$ file c
c: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9bfcfee9c3a5c078d45c8896a395f85c8216b029,
for GNU/Linux 4.4.0, not stripped
```
{: file='C'}

The compilation flags are almost the same, except for the presence of `debug_info` in Rust. Perhaps that's why the Rust binary has a larger size. By default, Rust statically links all libraries into the executable and includes symbols for debugging. However, when checking with the `file` command, it appears to recognize it as dynamically linked. To ensure we are dynamically linking it, let's use `rustc -C prefer-dynamic`.

By doing so, we were able to reduce the file size from **3.9 MB** to **17 KB**! It is now almost equivalent to the C binary, and we have eliminated the `debug_info`.
```console
$ file rust
rust: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=336b8052e7a465c6f3fdec0065e7a9407ea00451,
for GNU/Linux 4.4.0, not stripped
```
{: file='Rust'}

<br>

### Security Checks

Now let's check their security:
```console
$ checksec rust
[*] '/home/zeropio/Desktop/rustversing/rust'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
{: file='Rust'}

```console
$ checksec c
[*] '/home/zeropio/Desktop/rustversing/c'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
{: file='C'}

Oh! Rust has a default full RELRO, which theoretically decreases execution speed. However, considering all the techniques used by Rust and the statically linked libraries, this shouldn't be a problem. Upon further investigation, we discovered that Rust doesn't support Stack Canaries!

But neither does C add it by default. Compiling the C binary with the `-fstack-protector-all` flag will provide us with a stack canary. After participating in several CTFs, all of which employed stack canaries, and hearing numerous discussions about the importance of securing everything within a binary, I wondered why GCC doesn't enable it by default. After some research, I came across this report: [The Performance Cost of Shadow Stacks and Stack Canaries](https://people.eecs.berkeley.edu/~daw/papers/shadow-asiaccs15.pdf). While it's true that these measures may not provide the expected mitigation for binary exploitation, the decision to disable them by default due to performance issues seems kinda funny.

<br>

### Actual Reversing

Now it's time to reverse both binaries. Initially, I will be using BinaryNinja for this purpose. Later, I will compare different outputs with DogBolt.

#### Main Function

As soon as we open both files, differences start to show. First, let's take a look at the symbols:
![](/assets/img/research/rustversing/symbols-cmp.png)

> Note that all the `__builtin_...` functions are present in the Rust binaries as well, just below the screenshot.

<br>

The difference is quite evident, isn't it? The Rust binary has two different `main` functions: the actual `main` and (in this case) `rust::main::h2d88d26866781a19`. However, both binaries have the same `_start` function, with one significant difference afterward. In Rust, the `main` function calls the other `main` function:
![](/assets/img/research/rustversing/main-cmp-1.png)

<br>

As we can observe, the C `main` function calls the `hello` function. On the other hand, the Rust `hello` function is invoked within the `rust::main::h2d88d26866781a19` function:
![](/assets/img/research/rustversing/main-cmp-2.png)

C binaries save the RBP register, while Rust binaries save the RAX register. Quite curious, isn't it?

<br>

#### Hello Function

Let's move on to the `hello` function:
![](/assets/img/research/rustversing/hello-cmp-1.png)

<br>

As we can see, there are **significantly** more instructions in the Rust binaries compared to the C binaries. However, the main difference lies in the handling of strings. In the C binary, we have our hardcoded string there (without the variable), whereas in Rust, it is not immediately visible. The `var_40` seems to be holding the string we want to print inside `data_3d68`, but that section doesn't provide much information:
![](/assets/img/research/rustversing/rust-string-1.png)
_data_3d68 visualized_

We can attempt to construct a string from there, but it doesn't seem like a straightforward process:
![](/assets/img/research/rustversing/rust-string-2.png)
_data_3d68 as array of char_

<br>

Here's where things get interesting. When we examine the strings in both the C and Rust binaries, we notice a significant difference:
![](/assets/img/research/rustversing/rust-string-3.png)
_Only showing strings being used on the binary_

All the hardcoded strings in C are easily identifiable (although the variable `language` holding the char `C` is not visible because Binja searches for strings based on a minimum *hex-to-string* coincidence, so a larger word is needed for detection). However, the Rust strings appear within another block. We can see the value of the `language` variable (`Rust`) before the rest of the hardcoded string, but it is contained within another peculiar reference.

So, if Binja is identifying the string as being used, where is it? We can jump to the memory address and find it:
![](/assets/img/research/rustversing/rust-string-4.png)

Let's format it a bit:
![](/assets/img/research/rustversing/rust-string-5.png)

<br>

Now the `rust::hello` function appears to be clearer:
![](/assets/img/research/rustversing/rust-hello-1.png)

<br>

We have located our string. Now we need to understand how Rust prints it. In the C binary, the `printf` syscall is used to print the string. However, in Rust, it first calls `core::fmt::ArgumentV1::new_display`, then `core::fmt::Arguments::new_v1`, and finally returns `std::io::stdio::_print`. Using the Binja decompiler, we can obtain a clearer flow of the program. We can begin assigning names to variables to achieve a more organized view:
![](/assets/img/research/rustversing/rust-hello-2.png)

First, a pointer is set to the string we had. Then, Rust creates a **display** that points to it (a pointer to a pointer) and stores the **display** inside a variable called `string_display`. This display is then stored in a new variable, which will be the one passed to `_print`.

But what is `core::fmt::Arguments::new_v1`? It represents a vector! Rust strings are vectors of bytes (`Vec<u8>`). So, we have somewhat deduced the flow of the program.

<br>

### Final Thoughts

In summary, here are the key observations:

- The `_start` function calls the `main` function, similar to the C binary.
- The `main` function does not directly start the program but instead calls another main function - `rust::main`.
- The `rust::main` function calls the `rust::hello` function, just like the C binary.
- The `rust::hello` function retrieves the string and creates a Vector from it.
- The Vector is then passed to the `_print` function.

<br>
<br>
<br>

---

<br>

## Strings, Strings and Strings

Now that we have an idea of how Rust binaries can work, let's see how it handles different types of strings. In particular, we'll explore the differences between:

- `str`
- `String`
- Emojis in strings

The code for this example will be simple, just printing different types of strings:
```rust
fn main() {
    hello();
}

fn hello() {
    let var_str = "This is a str!";
    let var_string = String::from("This is a String");
    let emojis = "This are 🦀🦀🦀!";

    println!("{}", var_str);
    println!("{}", var_string);
    println!("{}", emojis);
}
```
{: file='rustversing.rs'}

We will start by using cargo to build the binaries. In this case, the resulting file will be **4 MB** in size. We can now check it as we did before:
```console
$ file target/debug/rustversing
target/debug/rustversing: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=576f4cca52f34e240a1185c7201a9bd89ed052d1, 
for GNU/Linux 4.4.0, with debug_info, not stripped
```
{: file='rustversing.rs'}

```console
$ checksec target/debug/rustversing
[*] '/home/zeropio/Code/Lang/Rust/rustversing/target/debug/rustversing'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
{: file='rustversing.rs'}

<br>

### Reversing It

The behavior remains the same as before. The `_start` function calls `main`, which in turn calls `rustversing::main`, and finally our `rustversing::hello` function. However, this time the function is a little bit different. We can observe this by viewing the graph:
<br>
![](/assets/img/research/rustversing/graph-1.png)

With our previous knowledge, we can now start cleaning up the binary. The High Level IL view is much cleaner than before. We can begin examining the strings and locate them, just as we did previously:
![](/assets/img/research/rustversing/strings-1.png)

What do we have here? We can see the delimiter we set (`!`) for the emojis, which helps us identify where that string ends. Additionally, we notice a pattern that repeats three times, matching the number of emojis we used. Therefore, we can conclude that the `🦀` emoji corresponds to the hex value `0xf09fa680`.
![](/assets/img/research/rustversing/rust-hello-3.png)

Finally, we can observe the same flow as before - a pointer to the string, creation of a display and a vector, and then passing the vector to the `_print` function. The binary doesn't appear to differentiate between `str` and `String`.

<br>

### Final Thoughts

- Emojis are saved as a hex value that the decompiler can't interpret. This can result in some strings being hidden from decompilers.
- At a low-level, there is no difference in how `str` and `String` are used.

<br>
<br>
<br>

---

<br>

## Get Some Input

Let's dive into more complex structures by obtaining user input and printing it:
```rust
use std::io;

fn main() {
    user_input();
}

fn user_input() {
    println!("Please enter some text:");

    let mut input = String::new();
    io::stdin().read_line(&mut input);

    println!("You entered: {}", input);
}
```
{: file='rustversing.rs'}

The file size remains the same as before, **4 MB**. Let's perform a few checks:
```console
$ file target/debug/rustversing
target/debug/rustversing: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0a9f48a6dc11be4a35ae86367b1d15cd9a8c4ef0,
for GNU/Linux 4.4.0, with debug_info, not stripped
```
{: file='rustversing.rs'}

```console
$ checksec target/debug/rustversing
[*] '/home/zeropio/Code/Lang/Rust/rustversing/target/debug/rustversing'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
{: file='rustversing.rs'}

<br>

### Reversing It

This binary is slightly different from all the previous ones. Firstly, the number of symbols has greatly increased:
![](/assets/img/research/rustversing/rust-symbols-1.png)

Perhaps due to the `use std::io;` import, we see all the functions listed there. Additionally, there are now many strings present. We can identify our hardcoded string, as well as some error management outputs:
![](/assets/img/research/rustversing/rust-strings-1.png)

<br>

And for the first time, we encounter some hardcoded strings:
![](/assets/img/research/rustversing/rust-user_input-1.png)

We can proceed to extract them as usual:
![](/assets/img/research/rustversing/rust-strings-2.png)

<br>

Returning to our `user_input` function, we can observe the creation of a `String` using the `alloc::string::String::new` function. Based on this line:
```c
6 @ 00008c78  void* var_58 = &std::io::stdio::stdin::INSTANCE::h98fb20affa94f4af
```

We can infer that `var_58` serves as an error handler, while the last variable (`var_68`) holds the actual input provided by the user. Then, as always, a vector is created with the contents of the string and passed to `_print` along with our `second_print` function:
![](/assets/img/research/rustversing/rust-user_input-2.png)

<br>

### Final Thoughts

- Rust always creates a `display` and `vector` for strings.
- Rust creates an error handler before calling `read_line`.

<br>
<br>
<br>

---

<br>

## Calling the System

In order to make system calls, we will use **libc** since we are working with a Linux host. Let's start by importing the dependency:
```toml
[dependencies]
libc = "0.2"
```
{: file='Cargo.toml'}

Now we can create our program:
```rust
extern crate libc;

fn main() {
    unsafe {
        let message = "Hello, World!\n";
        let len = message.len();

        let syscall_result = libc::write(libc::STDOUT_FILENO, message.as_ptr() as *const libc::c_void, len);
        
        if syscall_result == -1 {
            println!("Syscall failed");
        }
    }
}
```
{: file='main.rs'}

Notice how we need to encapsulate it within an `unsafe` block. System calls involve low-level control, and the `unsafe` block is used to signal to the Rust compiler that certain safety guarantees are being bypassed. Using syscalls can lead to incorrect usage. Therefore, we are implementing our own error handling in case of errors.

Let's do the checks:
```console
$ file target/debug/rustversing
target/debug/rustversing: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5b5498c5c59bd6016ee452254343a774958c1730, 
for GNU/Linux 4.4.0, with debug_info, not stripped
```
{: file='rustversing.rs'}

```console
$ checksec target/debug/rustversing
[*] '/home/zeropio/Code/Lang/Rust/rustversing/target/debug/rustversing'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
{: file='rustversing.rs'}

For this case, we are going to compare with a C program:
```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main() {
    char* message = "Hello, World!\n";
    size_t len = strlen(message);

    ssize_t syscall_result = write(STDOUT_FILENO, message, len);

    if (syscall_result == -1) {
        printf("Syscall failed\n");
    }

    return 0;
}
```
{: file='syscall.c'}

And its checks:
```console
$ file syscall
syscall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=06660856c07818cd0b2605b213da9cf4490ea962, 
for GNU/Linux 4.4.0, not stripped
```
{: file='syscall'}

```console
$ checksec syscall
[*] '/home/zeropio/Desktop/rustversing/syscall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
{: file='syscall'}


<br>

### Reversing It

First, let's examine the C binary. As expected, it is quite simple:
![](/assets/img/research/rustversing/c-syscall-1.png)
_C binary_

The Rust code appears to be larger... but why? In C, the program writes the string and then compares its length. If the length is valid, it uses `puts` to print it. However, in Rust, the output of `write` is saved to the `rax_2` variable. Then, the same comparison is made, and if it is valid, a vector is created with the string and the `_print` function is used to print it.
![](/assets/img/research/rustversing/rust-syscall-1.png)
_Rust binary_

<br>

### Final Thoughts

- Rust and C manifest similar behavior, but Rust always uses vectors as the underlying structure for printing strings.

<br>
<br>
<br>

---

<br>

## Some Binary Exploitation

I couldn't resist exploring some binary exploitation, even in Rust. However, for the purpose of this post, I focused on easily readable bugs. Here's what I came up with:
```rust
use std::io;

fn vulnerable_function(value: u32) {
    let mut result: u32 = 0;
    for i in 0..value {
        result += i;
    }
    println!("Result: {}", result);
}

fn main() {
    println!("Enter a value:");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read input.");
    let value: u32 = input.trim().parse().expect("Invalid input.");
    vulnerable_function(value);
}
```
{: file='main.rs'}

As you may have guessed, it involves an integer overflow. As soon as you send it `4294967294`, the program crashes:
```
Enter a value:
4294967294
thread 'main' panicked at 'attempt to add with overflow', src/main.rs:6:9
```

Let's do the check:
```console
$ file target/debug/rustversing
target/debug/rustversing: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=87d1b9d9da069d8d66c2e1fe035361e0c0d36cee, 
for GNU/Linux 4.4.0, with debug_info, not stripped
```
{: file='rustversing.rs'}

```console
$ checksec target/debug/rustversing
[*] '/home/zeropio/Code/Lang/Rust/rustversing/target/debug/rustversing'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
{: file='rustversing.rs'}

<br>

### Reversing It

![](/assets/img/research/rustversing/rust-integer-overflow-1.png)

Similar to before, the binary prompts the user for input (`std::io::stdio::Stdin::read_line`) and allocates a `String` from it. Then, it assigns the result to `rax_5` and passes it to the `rustversing::vulnerable_function` function. Notably, all the error messages are already hardcoded in the program. Unlike the earlier strings, Binja can access these strings.

#### Vulnerable Function

In this case, the graph for `rustversing::vulnerable_function` is more *complex*:
![](/assets/img/research/rustversing/graph-2.png)

Rust is calling the `_$LT$I$u20$as$u20$core.....tor$GT$::into_iter` function, which we can guess is the conversion of an iterator from our string. It then enters an infinite loop:
![](/assets/img/research/rustversing/rust-integer-overflow-2.png)
_First block_

The input is iterated byte by byte. If the byte is `0`, it jumps to the rest of the program, indicating that it executed correctly. While looping, the binary checks the least significant byte in the second `if` statement. If it is set, the program jumps to the `core::panicking::panic` function, terminating the execution.

At this point, panicking prevents the propagation of an integer overflow. Therefore, although Rust is not fully protected against it, it can handle it by terminating the program.
![](/assets/img/research/rustversing/rust-integer-overflow-3.png)
_Blurr to help focus_

If everything is correct, the program continues execution from where it left off.
![](/assets/img/research/rustversing/rust-integer-overflow-4.png)
_Last block_

<br>

### Final Thoughts

- Rust's panic handler helps prevent some exploitations.
- Unsafe blocks are not completely ignored by the compiler (some vulnerable codes attempted here returned errors).

<br>
<br>
<br>

---

<br>

## Final Notes

I would like to highlight that Rust, by default, allocates its structures on the heap. While attempting to explore "*Stack vs Heap*", I discovered that Rust seems to use the heap for almost everything, including vectors (which constitute the majority of the data) and boxes. Perhaps in future posts, I will explore deeper into this topic and provide more insights.

From this overview, we can conclude the following:
- The `_start` function calls the `main` function, similar to the C binary.
- The `main` function doesn't start the program directly; instead, it calls another main function: `rust::main`.
- The `rust::main` function calls the `rust::hello` function, just like the C binary.
- The `rust::hello` function retrieves the string and creates a vector from it.
- The vector is then passed to the `_print` function.
- Emojis are saved as hex values that the decompiler can't interpret, potentially hiding some strings from decompilers.
- At a low level, there is no difference in how `str` and `String` are used.
- Rust always creates a `display` and `vector` for strings.
- Rust creates an error handler before calling `read_line`.
- Rust and C exhibit similar behavior, but Rust always uses vectors as the underlying structure for printing strings.
- The panic handler in Rust helps prevent some exploitations.
- Unsafe blocks are not completely ignored by the compiler.

Although I feel that there is much more to explore, I don't want to write an excessively lengthy post reviewing every Rust struct in detail — at least not in a single post. In future posts, I plan to delve into more structs, malware, and binary exploitation.

Stay tuned!

<br>
<br>
<br>

---

<br>

## References

- [The Performance Cost of Shadow Stacks and Stack Canaries](https://people.eecs.berkeley.edu/~daw/papers/shadow-asiaccs15.pdf)
- [Rust By Examples - Strings](https://doc.rust-lang.org/rust-by-example/std/str.html)
- [std::io::Stdin Rust Doc](https://doc.rust-lang.org/std/io/struct.Stdin.html)