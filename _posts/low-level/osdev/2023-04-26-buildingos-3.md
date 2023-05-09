---
title: OSDev | Chapter 3 | Interrupts
author: x4sh3s
date: 2023-04-26
categories: [LowLevel, OSDev]
tags: [lowlevel, osdev]
permalink: /lowlevel/osdev/chapter-3
---

## Introduction

To create a functional OS, it is essential to handle errors such as division by zero, attempts to access non-existent memory addresses, and other potential issues. One approach to handling errors is to create an *interrupt descriptor table*[^footnote]. Additionally, using different structs can also provide a better understanding of the system's overall structure and organization.

<br>

---

## CPU Exceptions

Exceptions occur when an error happens, causing the CPU to stop its current work and call an exception handler function. Some types of exceptions are:

<h4>Faults</h4>

- **Division Error**: occurs when dividing by 0 using `DIV` or `IDIV`.
- **Invalid Opcode**: happens when the processor tries to execute an invalid, undefined opcode, or with invalid prefixes.
- **Stack-Segment Fault**: occurs when loading a stack-segment referencing a segment descriptor that is not present, pushing or popping any instruction using ESP or EBP, or when the stack-limit check fails.
- **General Protection Fault**: can occur due to a segment error, executing a privileged instruction while `CPL != 0`[^fn-nth-2], writing a 1 in a reserved register field or writing invalid value combinations, or referencing or accessing a null-descriptor.
- **Page Fault**: happens when a page directory or table entry is not present in physical memory, when a protection check fails, or when the reserved bit in the page directory or table entries is set to 1.

<h4>Traps</h4>

- **Debug**: can occur due to various reasons such as instruction fetch breakpoint (Fault), general detect condition (Fault), data read or write breakpoint (Trap), I/O read or write breakpoint (Trap), Single-step (Trap), or Task-switch (Trap).
- **Breakpoint**: occurs when the INT3 instruction is executed.
- **Overflow**:  occurs when the INTO instruction is executed while the overflow bit in RFLAGS is set to 1.

<h4>Aborts</h4>

- **Double Fault**: occurs when an exception is unhandled or when an exception occurs while the CPU is trying to call an exception handler.
- **Triple Fault**: not really an exception as it doesn't have an associated vector number. It occurs when an exception is generated when an attempt is made to call the double fault exception handler.

To build the **IDT** (**I**nterrupt **D**escriptor **T**able), we need to add values in the 16-byte structure because the hardware accesses this table. Each entry must include the following fields:

| **Type** | **Name** | **Description** |
| -------- | -------- | --------------- |
| `u16` | Function Pointer [0:15] | Lower bits of the pointer to the handler function |
| `u16` | GDT selector | Selector in the *Global Descriptor Table*[^fn-nth-3] |
| `u16` | Options | (second table) |
| `u16` | Function Pointer [16:31] | Middle bits of the pointer |
| `u32` | Function Pointer [32:63] | Lasts bits of the pointer |
| `u32` | Reserved | |

The *options* fields follow this format:

| **Bits** | **Name** | **Description** |
| -------- | -------- | --------------- |
| 0 - 2 | **Interrupt Stack Table Index** | 0: Don’t switch stacks, 1-7: Switch to the n-th stack in the Interrupt Stack Table when this handler is called |
| 3 - 7 | Reserved | |
| 8 | Gate | If 0 (*Interrupt Gate*), interrupts are disabled when this handler is called |
| 9 - 11 | must be 1 | |
| 12 | must be 0 | |
| 13 - 14 | **Descriptor Privilege Level** (**DPL**) | minimal privilege level required for calling this handler |
| 15 | Present | |

When a exception is called, the following occurs on the CPU:
1. The registers are pushed onto the stack.
2. The entry from the **IDT** is read.
3. If the entry is not present, a double fault is raised.
4. If the entry is an interrupt gate, hardware interrupts are disabled.
5. The **GDT** is loaded into the *code segment*.
6. The specified handler function is then executed.

### IDT Structure

Rust already provides an [IDT](https://docs.rs/x86_64/0.14.2/x86_64/structures/idt/struct.InterruptDescriptorTable.html) that we can use:
```rust
#[repr(C)]
pub struct InterruptDescriptorTable {
    pub divide_by_zero: Entry<HandlerFunc>,
    pub debug: Entry<HandlerFunc>,
    pub non_maskable_interrupt: Entry<HandlerFunc>,
    pub breakpoint: Entry<HandlerFunc>,
    pub overflow: Entry<HandlerFunc>,
    pub bound_range_exceeded: Entry<HandlerFunc>,
    pub invalid_opcode: Entry<HandlerFunc>,
    pub device_not_available: Entry<HandlerFunc>,
    pub double_fault: Entry<HandlerFuncWithErrCode>,
    pub invalid_tss: Entry<HandlerFuncWithErrCode>,
    pub segment_not_present: Entry<HandlerFuncWithErrCode>,
    pub stack_segment_fault: Entry<HandlerFuncWithErrCode>,
    pub general_protection_fault: Entry<HandlerFuncWithErrCode>,
    pub page_fault: Entry<PageFaultHandlerFunc>,
    pub x87_floating_point: Entry<HandlerFunc>,
    pub alignment_check: Entry<HandlerFuncWithErrCode>,
    pub machine_check: Entry<HandlerFunc>,
    pub simd_floating_point: Entry<HandlerFunc>,
    pub virtualization: Entry<HandlerFunc>,
    pub security_exception: Entry<HandlerFuncWithErrCode>,
}
```

We will modify `src/lib.rs`{: .filepath} and create a new `src/interrupts.rs`{: .filepath} file to create an interrupts module.
```rust
pub mod interrupts;
```
{: file='src/lib.rs'}

```rust
use x86_64::structures::idt::InterruptDescriptorTable;

pub fn init_idt() {
    let mut idt = InterruptDescriptorTable::new();
}
```
{: file='src/interrupts.rs'}

We can start by implementing the breakpoint exception, which occurs when the `int3` instruction is executed:
```rust
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use crate::println;

pub fn init_idt() {
    let mut idt = InterruptDescriptorTable::new();
    idt.breakpoint.set_handler_fn(breakpoint_handler);
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame)
{
    println!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}
```
{: file='src/interrupts.rs'}

This will drop an error, so we need to add `#![feature(abi_x86_interrupt)]` to `lib.rs`{: .filepath} to handle it.

### Loading the IDT

We can load the IDT as follows:
```rust
pub fn init_idt() {
    let mut idt = InterruptDescriptorTable::new();
    idt.breakpoint.set_handler_fn(breakpoint_handler);
    idt.load();
}
```
{: file='src/interrupts.rs'}

However, this will drop an error because `idt` is borrowed. To handle it, we can use the `lazy_static` macro again:
```rust
use lazy_static::lazy_static;

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt
    };
}

pub fn init_idt() {
    IDT.load();
}
```
{: file='src/interrupts.rs'}

Now, add the function to `lib.rs`{: .filepath}:
```rust
pub fn init() {
    interrupts::init_idt();
}
```
{: file='src/lib.rs'}

And modify the `_start` function to call the handler:
```rust
#[no_mangle]
pub extern "C" fn _start() -> ! {
    println!("Hello World!");

    zeros::init();

    x86_64::instructions::interrupts::int3();

    #[cfg(test)]
    test_main();

    println!("It did not crash!");
    loop {}
}
```
{: file='src/main.rs'}

### Error Visualizer

Finally, we can see the error on screen:

![](/assets/img/osdev/2023-04-26_17-41.png)
_Exception Handled_

<br>

---

## Double Faults

To avoid triple faults (which restart the system), we need to handle double faults. As mentioned before, a double fault occurs when the CPU fails to invoke an exception handler. We can easily provoke this error with the following code:
```rust
zeros::init();

unsafe {
    *(0xdeadc0ffe as *mut u64) = 1337;
}
```
{: file='src/main.rs'}

This will cause the kernel to crash.

### The Handler

To handle double faults, we need to add some lines to `interrupts.rs`{: .filepath}. We need to add a new entry to the IDT and define a new function for it:
```rust
lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.double_fault.set_handler_fn(double_fault_handler); // double fault added
        idt
    };
}

extern "x86-interrupt" fn double_fault_handler(stack_frame: InterruptStackFrame, _error_code: u64) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}
```
{: file='src/interrupts.rs'}

### Kernel Stack Overflow and Switching Stacks

We can easily create a stack overflow by creating an infinite loop:
```rust
fn stack_overflow() {
        stack_overflow(); // for each recursion, the return address is pushed
}

stack_overflow();
```

This will cause the OS to enter an infinite restart loop:

![](/assets/img/osdev/2023-04-26-18-40.gif)
_Kernel Stack Overflow_

To prevent this error, we can use **Switching Stacks**. This is implemented as the **IST** (**I**nterrupt **S**tack **T**able), which is a table of 7 pointers to known-good stacks. It is part of an older structure called the **TSS** (**T**ask **S**tate **S**egment), which was used to save some information for hardware context switching. However, in 64-bit systems, hardware context switching is no longer supported.

In 64-bit systems, the TSS holds the IST and the **Privilege Stack Table**.


Now, we will create a **Global Descriptor Table** file (`src/gdt.rs`{: .filepath}). Add the following line to `lib.rs`{: .filepath}:
```rust
pub mod gdt;
```
{: file='src/lib.rs'}

In the newly created `gdt.rs`{: .filepath} file, we create the TTS:
```rust
use x86_64::VirtAddr;
use x86_64::structures::tss::TaskStateSegment;
use lazy_static::lazy_static;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

lazy_static! {
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 4096 * 5;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

            let stack_start = VirtAddr::from_ptr(unsafe { &STACK });
            let stack_end = stack_start + STACK_SIZE;
            stack_end
        };
        tss
    };
}
```
{: file='src/gdt.rs'}

With the TSS created, we need to create the GDT:
```rust
use x86_64::structures::gdt::{GlobalDescriptorTable, Descriptor, SegmentSelector};

lazy_static! {
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        let code_selector = gdt.add_entry(Descriptor::kernel_code_segment());
        let tss_selector = gdt.add_entry(Descriptor::tss_segment(&TSS));
        (gdt, Selectors { code_selector, tss_selector })
    };
}

struct Selectors {
    code_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}
```
{: file='src/gdt.rs'}

To load the GDT, create an `ìnit()` function:
```rust
pub fn init() {
    use x86_64::instructions::tables::load_tss;
    use x86_64::instructions::segmentation::{CS, Segment};

    GDT.0.load();
    unsafe {
        CS::set_reg(GDT.1.code_selector);
        load_tss(GDT.1.tss_selector);
    }
}
```
{: file='src/gdt.rs'}

And load it into `lib.rs`{: .filepath}:
```rust
pub fn init() {
    gdt::init();
    interrupts::init_idt();
}
```
{: file='src/lib.rs'}

Finally, we need to add `.set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);` to the `double_fault_handler` on `interrupts.rs`{: .filepath} inside an `unsafe` block. And modify the function to:
```rust
extern "x86-interrupt" fn double_fault_handler(stack_frame: InterruptStackFrame, _error_code: u64) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{:#?}", stack_frame);
}
```
{: file='src/interrupts.rs'}

And now, when a kernel stack overflow happens the OS will stop:

![](/assets/img/osdev/2023-04-26_19-04.png)
_Double Fault Handled_

<br>

---

## Hardware Interrupts

Hardware interrupts allow us to notify the CPU about some attached hardware. Instead of checking if the keyboard is pressed every time we press it, an instruction will be sent to the kernel. First, we need to create an **Interrupt Controller**, because we can't attach an unlimited amount of hardware to the CPU.

To create the interrupt controller, we will simulate the *8259* and *8259A* **PICs** (**P**rogrammable **I**nterrupt **C**ontrollers) with the [pic8259](https://crates.io/crates/pic8259) crate. Add it to the dependencies:
```toml
[dependencies]
pic8259 = "0.10.1"
```
{: file='Cargo.toml'}

In `src/interrupts.rs`{: .filepath} we need to create the `ChainedPics` struct that the crate provides:
```rust
use pic8259::ChainedPics;
use spin;

pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub static PICS: spin::Mutex<ChainedPics> = spin::Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });
```
{: file='src/interrupts.rs'}

We can now initiliaze it in `lib.rs`{: .filepath} and allow interrupts:
```rust
pub fn init() {
    gdt::init();
    interrupts::init_idt();
    unsafe { interrupts::PICS.lock().initialize() };
    x86_64::instructions::interrupts::enable();
}
```
{: file='src/lib.rs'}

However, executing it will drop an error. This happens because interrupts are enabled, and the system is waiting for time interrupts.

![](/assets/img/osdev/2023-04-26_19-47.png)
_Double Fault Error_

### Handling Time Interrupts

We create a C-like enum for the interrupt:
```rust
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}
```
{: file='src/interrupts.rs'}

Now we can add a new handler to the IDT::
```rust
idt[InterruptIndex::Timer.as_usize()].set_handler_fn(timer_interrupt_handler);
```

And add the function:
```rust
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    print!(".");
}
```
{: file='src/interrupts.rs'}

Now the system wait without crashing. But a new problem arises: we need to specify the **EOI** (**E**nd **O**f **I**nterrupt) to say that the current interrupt has ended and start the following:
```rust
extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    print!(".");

    unsafe {
        PICS.lock().notify_end_of_interrupt(InterruptIndex::Timer.as_u8());
    }
}
```
{: file='src/interrupts.rs'}

This will print the text an unlimited times.

![](/assets/img/osdev/2023-04-26_20-01.png)
_Printing_


### Deadlocks

Deadlocks occurs if a thread tries to lock a process. The print we used provokes one, not allowing the rest of the kernel to execute. To avoid this error we can modify the function `print` from `vga_buffer.rs`{: .filepath}:
```rust
#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    use x86_64::instructions::interrupts;

    interrupts::without_interrupts(|| {
        WRITER.lock().write_fmt(args).unwrap();
    });
}
```
{: file='src/vga_buffer.rs'}

### htl Instruction

We have used a `loop{}` at the end of the `_start` function to make it run, but this is a poorly efficient way of doing it. This makes the CPU works at full speed even though there is no work to do. We need to *halt* the CPU until the next interrupts, so the CPU enters in a sleep mode until then.

For this, we create a new function:
```rust
pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}
```
{: file='src/lib.rs'}

And now replace the `loop{}` with `zeros::hlt_loop()`.

### Keyboard Input

With everything set, we can now add keyboard input. We need to handle a new interrupt this time:
```rust
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard
}

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        unsafe {idt.double_fault.set_handler_fn(double_fault_handler).set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);}
        idt[InterruptIndex::Timer.as_usize()].set_handler_fn(timer_interrupt_handler);
        idt[InterruptIndex::Keyboard.as_usize()].set_handler_fn(keyboard_interrupt_handler);
        idt
    };
}

extern "x86-interrupt" fn keyboard_interrupt_handler(_stack_frame: InterruptStackFrame) {
    print!("");

    unsafe {
        PICS.lock().notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}
```
{: file='src/interrupts.rs'}

Now we need to read the codes we input:
```rust
extern "x86-interrupt" fn keyboard_interrupt_handler(
    _stack_frame: InterruptStackFrame)
{
    use x86_64::instructions::port::Port;

    let mut port = Port::new(0x60);
    let scancode: u8 = unsafe { port.read() };
    print!("{}", scancode);

    unsafe {
        PICS.lock().notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}
```
{: file='src/interrupts.rs'}

But we have *scancodes* instead of actual characters. We can use the [pc-keyboard](https://crates.io/crates/pc-keyboard) crate for this. Import it:
```toml
[dependencies]
pc-keyboard = "0.5.0"
```
{: file='Cargo.toml'}

And modify the previous code:
```rust
extern "x86-interrupt" fn keyboard_interrupt_handler(
    _stack_frame: InterruptStackFrame)
{
    use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};
    use spin::Mutex;
    use x86_64::instructions::port::Port;

    lazy_static! {
        static ref KEYBOARD: Mutex<Keyboard<layouts::Us104Key, ScancodeSet1>> =
            Mutex::new(Keyboard::new(layouts::Us104Key, ScancodeSet1,
                HandleControl::Ignore)
            );
    }

    let mut keyboard = KEYBOARD.lock();
    let mut port = Port::new(0x60);

    let scancode: u8 = unsafe { port.read() };
    if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
        if let Some(key) = keyboard.process_keyevent(key_event) {
            match key {
                DecodedKey::Unicode(character) => print!("{}", character),
                DecodedKey::RawKey(key) => print!("{:?}", key),
            }
        }
    }

    unsafe {
        PICS.lock()
            .notify_end_of_interrupt(InterruptIndex::Keyboard.as_u8());
    }
}
```
{: file='src/interrupts.rs'}

![](/assets/img/osdev/2023-04-26-20-27.gif)
_Writing Input!_

<br>

---

## References

- [CPU Exceptions](https://os.phil-opp.com/cpu-exceptions/)
- [Interrupt Descriptor Table](https://en.wikipedia.org/wiki/Interrupt_descriptor_table)
- [OSDev Wiki Exceptions](https://wiki.osdev.org/Exceptions)
- [CPL Instruction](https://wikidev.in/wiki/assembly/8051/CPL)
- [Global Descriptor Table](https://en.wikipedia.org/wiki/Global_Descriptor_Table)
- [Double Faults](https://os.phil-opp.com/double-fault-exceptions/)
- [Hardware Interrupts](https://os.phil-opp.com/hardware-interrupts/)
- [Deadlock](https://en.wikipedia.org/wiki/Deadlock)


<br>

---

## Footnotes

[^footnote]: is a data structure used by the x86 architecture to implement an *interrupt vector table*. which links a list of interrupt handlers with a list of interrupt requests.
[^fn-nth-2]: the CPL instruction complements the value of the specified destination operand and stores the result back in the destination operand. Bits that previously contained a 1 will be changed to a 0 and bits that previously contained a 0 will be changed to a 1.
[^fn-nth-3]: is a data structure used by Intel x86-family processors to define the characteristics of the various memory areas used during program execution, including the base address, the size, and access privileges like executability and writability.
