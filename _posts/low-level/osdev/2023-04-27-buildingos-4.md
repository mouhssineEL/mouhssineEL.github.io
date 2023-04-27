---
title: OSDev | Chapter 4 | Memory Management
author: Zeropio
date: 2023-04-27
categories: [LowLevel, OSDev]
tags: [lowlevel, osdev]
permalink: /lowlevel/osdev/chapter-4
---

# Introduction

In this part, we will implement two key memory management features: paging, which enables mapping physical memory to virtual memory, and heap allocation, which provides dynamic memory allocation for processes.

<br>

---

# Paging

Memory access for each program should be independent from others. One process should not be able to access the memory of another process. **Segmentation** and **paging** allow us to achieve this.

Segmentation creates *virtual memory*, where a piece of memory is reserved and isolated for a process. Each block of memory for each process of virtual memory is allocated on the physical memory, plus an offset. This makes each process have a different space of the memory. However, segmentation is not typically used in modern systems due to fragmentation. If we want to add new virtual memory for a new process, but there is not a whole chunk we can use, the previous chunks are reallocated in the physical memory. This makes the CPU stop processes at random times, move big blocks of data, and lower the performance.

![](/assets/img/osdev/Segmentation-1.png)
_First Step Fragmentation_

<br>

![](/assets/img/osdev/Segmentation-2.png)
_Second Step Fragmentation_

With paging, instead of creating big chunks of addresses for a process, we split the virtual memory into small chunks and reallocate it without problems:

![](/assets/img/osdev/Pagination-1.png)
_First Step Pagination_

<br>

![](/assets/img/osdev/Pagination-2.png)
_Second Step Pagination_

As we can see, paging uses a lot of small blocks instead of one big block. There is still some fragmentation (called *internal fragmentation*). This internal fragmentation is not fixed; some blocks can have different sizes between them. Because of the *chaotic* appearance, paging has **Page Tables** where each process has its own, mapping all the sections. This table is stored as a pointer to it on the CR3 register. All this work is done at the hardware level.

For size optimization, some page tables can leave empty chunks. Because of this, instead of having one page table, we have one main page table that links to one page table for each group of segmentations. On x86_64, we have a 4-level page table. Each page table has a fixed size of **512 entries**. Each entry has a size of 8 bytes.

In Rust, we can create a page table as follows:
```rust
#[repr(align(4096))]
pub struct PageTable {
    entries: [PageTableEntry; 512],
}
```

As each entry is 8 bytes large, we have the following format:

| **Bit** | **Name** | **Description** |
| ------- | -------- | --------------- |
| 0 | present | the page is in memory |
| 1 | writable | allowed to write |
| 2 | user accessible | if not set, only kernel mode can access |
| 3 | write-through caching | writes go to memory |
| 4 | disable cache | no cache |
| 5 | accessed | sets if this page is used |
| 6 | dirty | set when a write occurs |
| 7 | huge page/null | must be 0 in P1 and P4, creates a 1 GiB page in P3, creates a 2 MiB page in P2 |
| 8 | global | page isn’t flushed from caches on address space switch |
| 9 - 11 | available | can be used freely by the OS |
| 12 - 51 | physical address | the page aligned 52-bit physical address of the frame or the next page table |
| 52 - 62 | available | can be used freely by the OS |
| 63 | no execute | forbids executing code on this page (NXE) |

The kernel we have written already works on 4-level paging due to being in 64-bit mode.

<br>

---

# Implementation

## Page Fault
We can create a **page fault** by accessing a non-existent region. First, edit `src/interrupts.rs`{: .filepath}:
```rust
lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        ...
        idt.page_fault.set_handler_fn(page_fault_handler);
        idt
    };
}

use x86_64::structures::idt::PageFaultErrorCode;
use crate::hlt_loop;

extern "x86-interrupt" fn page_fault_handler(stack_frame: InterruptStackFrame, error_code: PageFaultErrorCode) {
    use x86_64::registers::control::Cr2;

    println!("EXCEPTION: PAGE FAULT");
    println!("Accessed Address: {:?}", Cr2::read());
    println!("Error Code: {:?}", error_code);
    println!("{:#?}", stack_frame);
    hlt_loop();
}
```
{: file='src/interrupts.rs'}

And now, access memory from outside the kernel:
```rust
let ptr = 0xdeadbeaf as *mut u32;
unsafe { *ptr = 42; }
```
{: file='src/main.rs'}

The problem with the page tables is that they are stored in physical memory, and the kernel can only access virtual memory. To access the page tables, we need the bootloader. We can take different approaches to it, like:
- **Identity Mapping**: cloning the physical memory to the virtual memory to have an exact copy of the page tables. But here we have the problem of segmentation.
- **Map a Fixed Offset**: to avoid cluttering, we can use a separate memory region for page table mappings.
- **Mapping Physical Memory**: instead of just mapping the page table, we can map the entire physical memory.
- **Temporary Mapping**: we can map the page table frames only when we need it.
- **Recursive Page Tables**: instead of creating new tables, we can map the level 4 page table to the level 4 table itself.

## Return to the Bootloader

We will need to use the previously used **bootloader** crate, with the `map_physical_memory` feature:
```toml
[dependencies]
bootloader = { version = "0.9.23", features = ["map_physical_memory"]}
```
{: file='Cargo.toml'}

Now, the bootloader maps the complete physical memory to some virtual address range and passes a *boot information* structure to the kernel. This crate includes a `BootInfo` struct. Currently, it contains two values: `memory_map` (an overview of the available physical memory) and `physical_memory_offset` (the virtual start address of the physical memory mapping).

Now we need to set it on `src/main.rs`{: .filepath}. The crate provides the `entry_point` macro that sets everything for us. We don't need to create our own `_start`, since `entry_point` will be doing it. We need to import the crate, set the entry point, replace the `_start` function with a new `kernel_main`, and we don't need to specify `no_mangle` anymore:
```rust
use bootloader::{BootInfo, entry_point};

entry_point!(kernel_main);

fn kernel_main(boot_info: &'static BootInfo) -> ! {
    […]
}
```
{: file='src/main.rs'}

## Page Tables

Now we can implement the page tables. Import a new module and create a new `src/memory.rs`{: .filepath}:
```rust
pub mod memory;
```
{: file='src/lib.rs'}

We are going to create a reader for the level 4 page table. First, read the physical frame of the level 4 table from the CR3 register. Add the physical start address to `physical_memory_offset` to get the virtual address and create an unsafe pointer to it:
```rust
use x86_64::{
    structures::paging::PageTable,
    VirtAddr,
};

pub unsafe fn active_level_4_table(physical_memory_offset: VirtAddr)
    -> &'static mut PageTable
{
    use x86_64::registers::control::Cr3;

    let (level_4_table_frame, _) = Cr3::read();

    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    &mut *page_table_ptr // unsafe
}
```
{: file='src/memory.rs'}

Using this reader, we can print the entries of the level 4 table.
```rust
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    use zeros::memory::active_level_4_table;
    use x86_64::VirtAddr;

    println!("Hello World{}", "!");
    blog_os::init();

    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset);
    let l4_table = unsafe { active_level_4_table(phys_mem_offset) };

    for (i, entry) in l4_table.iter().enumerate() {
        if !entry.is_unused() {
            println!("L4 Entry {}: {:?}", i, entry);
        }
    }
}
```
{: file='src/main.rs'}

We can now see the contents:

![](/assets/img/osdev/2023-04-27_18-34.png)
_Level 4 Table_

Let's take a closer look at the lower levels of the page tables:
```rust
for (i, entry) in l4_table.iter().enumerate() {
        use x86_64::structures::paging::PageTable;

        if !entry.is_unused() {
            println!("L4 Entry {}: {:?}", i, entry);

            let phys = entry.frame().unwrap().start_address();
            let virt = phys.as_u64() + boot_info.physical_memory_offset;
            let ptr = VirtAddr::new(virt).as_mut_ptr();
            let l3_table: &PageTable = unsafe { &*ptr };

            for (i, entry) in l3_table.iter().enumerate() {
                if !entry.is_unused() {
                    println!("  L3 Entry {}: {:?}", i, entry);
                }
            }
        }
    }
```
{: file='src/main.rs'}

## Translating

We can create a function to translate physical addresses to virtual memory addresses with the `x86_64` crate's `OffsetPageTable` function:
```rust
use x86_64::structures::paging::OffsetPageTable;

pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let level_4_table = active_level_4_table(physical_memory_offset);
    OffsetPageTable::new(level_4_table, physical_memory_offset)
}
```
{: file='src/memory.rs'}

## New Mapping
Instead of reading page tables, we are going to create new mappings. First, we need to create a frame allocator. We can do it with the `bootloader` crate. We made an iterator of usable frames before:
```rust
use x86_64::{
    structures::paging::{PageTable, OffsetPageTable, PhysFrame, Size4KiB, FrameAllocator},
    VirtAddr,
    PhysAddr
};
use bootloader::bootinfo::{MemoryMap, MemoryRegionType};
pub struct BootInfoFrameAllocator {
    memory_map: &'static MemoryMap,
    next: usize,
}

impl BootInfoFrameAllocator {
    pub unsafe fn init(memory_map: &'static MemoryMap) -> Self {
        BootInfoFrameAllocator {
            memory_map,
            next: 0,
        }
    }
}

impl BootInfoFrameAllocator {
    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> {
        let regions = self.memory_map.iter();
        let usable_regions = regions
            .filter(|r| r.region_type == MemoryRegionType::Usable);
        let addr_ranges = usable_regions
            .map(|r| r.range.start_addr()..r.range.end_addr());
        let frame_addresses = addr_ranges.flat_map(|r| r.step_by(4096));
        frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}
```
{: file='src/memory.rs'}

The function:
1. Converts the memory map to an iterator of `MemoryRegion`
2. Uses `filter` to remove unavailable regions
3. Uses `map` to transform our iterator of memory regions to an iterator of address ranges
4. Uses `flat_map` to transform the address ranges into an iterator of frame start addresses
5. Converts the start address to `PhysFrame`

Next, we will implement the `FrameAllocator` trait:
```rust
unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}
```
{: file='src/memory.rs'}

<br>

---

# Heap Allocation

There are two types of variables: **local** variables and **static** variables. Local variables are stored on the *call stack*[^footnote] and are only valid until the surrounding function returns.

Static variables (`'static`) are stored at a fixed memory location separate from the stack. This memory is assigned at compile time by the linker. Statics live for the complete runtime of the program and are by default read-only to prevent data races. To modify a static variable, we need to encapsulate it in a `Mutex` type.

Both local and static variables have a fixed size. Because of this downside, programming languages usually provide a third option called the **heap**. The heap is a dynamic memory allocation at runtime with two functions: `allocate` and `deallocate`. The `allocate` function returns a free chunk of memory, while `deallocate` frees the chunk. This chunk is valid until `deallocate` is called. The advantage of using heap memory compared to static memory is that the memory can be reused after it is freed. However, this can also lead to new errors such as *memory leaks*, *use-after-free*, *double-free*, etc. This is where **garbage collection** or **ownership** in Rust takes action.

Using the heap in the kernel is necessary when we need to start using structs like `Vec` or `String` that grow in size.

## The Allocator
First, we need to create the heap allocator with the built-in `alloc` crate. To add it to the default compiler:
```rust
extern crate alloc;
```
{: file='src/lib.rs'}

And add it to the default compiler:
```toml
[unstable]
build-std = ["core", "compiler_builtins", "alloc"]
```
{: file='.cargo/config.toml'}

This will provoke some errors because `alloc` depends on the `GlobalAlloc` trait, which implements `alloc` and `dealloc`, as well as `alloc_zeroed` (allocated and set to zero) and `realloc` (resize chunks). Now we need to recreate these functions in our program in a new file: `src/allocator.rs`{: .filepath}:
```rust
pub mod allocator;
```
{: file='src/lib.rs'}

```rust
use alloc::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

pub struct Dummy;

unsafe impl GlobalAlloc for Dummy {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        null_mut()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        panic!("dealloc should be never called")
    }
}
```
{: file='src/allocator.rs'}

Next, we must define the `#[global_allocator]` and `#[alloc_error_handler]` attributes:
```rust
#[global_allocator]
static ALLOCATOR: Dummy = Dummy;
```
{: file='src/allocator.rs'}

```rust
#![feature(alloc_error_handler)] // at the top of the file

#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("allocation error: {:?}", layout)
}
```
{: file='src/lib.rs'}

## The Kernel Heap

Before creating an allocator, we need to reserve a space in memory for the heap. We can use the previous functions we created for memory mapping to do this. Let's give it a starting address:
```rust
pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 100 * 1024; // 100 KiB
```
{: file='src/allocator.rs'}

Now we need to map it to physical memory:
```rust
use x86_64::{
    structures::paging::{
        mapper::MapToError, FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB,
    },
    VirtAddr,
};

pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
    let page_range = {
        let heap_start = VirtAddr::new(HEAP_START as u64);
        let heap_end = heap_start + HEAP_SIZE - 1u64;
        let heap_start_page = Page::containing_address(heap_start);
        let heap_end_page = Page::containing_address(heap_end);
        Page::range_inclusive(heap_start_page, heap_end_page)
    };

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush()
        };
    }

    Ok(())
}
```
{: file='src/allocator.rs'}

Here's what's happening:
- **Creating the page range**: we convert `HEAP_START` to a `VirtAddr` type, calculate the heap address, convert the addresses to `Page` type and create a page range from the start to end.
- **Mapping the pages**: now we map all pages of the page range. We iterate over them and:
    - Allocate a physical frame for the page that should be mapped.
    - Set the `PRESENT` and `WRITABLE` flags.
    - Create the mapping in the active page table.

Finally, we need to call the function in `kernel_main`:
```rust
    use zeros::allocator;
    use zeros::memory::{self, BootInfoFrameAllocator};
    use x86_64::VirtAddr;

    zeros::init();

    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = unsafe { memory::init(phys_mem_offset) };
    let mut frame_allocator = unsafe {
        BootInfoFrameAllocator::init(&boot_info.memory_map)
    };

    allocator::init_heap(&mut mapper, &mut frame_allocator)
        .expect("heap initialization failed");

    let x = Box::new(41); // for test
```
{: file='src/main.rs'}

## Allocator Crate

We are going to use the [linked_list_allocator](https://crates.io/crates/linked_list_allocator) crate for our allocator. To add it, we include it as a dependency:
```toml
[dependencies]
linked_list_allocator = "0.9.0"
```
{: file='Cargo.toml'}

We can replace the `dummy` allocator with it:
```rust
use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();
```
{: file='src/allocator.rs'}

Now, we need to initialize the allocator after creating the heap:
```rust
pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
  [...]

  unsafe {
        ALLOCATOR.lock().init(HEAP_START, HEAP_SIZE);
    }

    Ok(())
}
```
{: file='src/allocator.rs'}

## Testing

We can go back to `kernel_main` and test it as follows:
```rust
fn kernel_main(boot_info: &'static BootInfo) -> ! {
    use zeros::allocator;
    use zeros::memory::{self, BootInfoFrameAllocator};
    use x86_64::VirtAddr;

    zeros::init();

    let phys_mem_offset = VirtAddr::new(boot_info.physical_memory_offset);
    let mut mapper = unsafe { memory::init(phys_mem_offset) };
    let mut frame_allocator = unsafe { BootInfoFrameAllocator::init(&boot_info.memory_map) };

    allocator::init_heap(&mut mapper, &mut frame_allocator).expect("heap initialization failed");

    let heap_value = Box::new(41);
    println!("heap_value at {:p}", heap_value);

    let mut vec = Vec::new();
    for i in 0..500 {
        vec.push(i);
    }
    println!("vec at {:p}", vec.as_slice());

    let reference_counted = Rc::new(vec![1, 2, 3]);
    let cloned_reference = reference_counted.clone();
    println!(
        "current reference count is {}",
        Rc::strong_count(&cloned_reference)
    );
    core::mem::drop(reference_counted);
    println!(
        "reference count is {} now",
        Rc::strong_count(&cloned_reference)
    );

    zeros::hlt_loop();
}
```
{: file='src/main.rs'}

![](/assets/img/osdev/2023-04-27_20-20.png)
_Heap Allocation_

<br>

---

# References

- Images done on [Figma](https://www.figma.com/)
- [Introduction to Paging](https://os.phil-opp.com/paging-introduction/)
- [Paging Implementation](https://os.phil-opp.com/paging-implementation/)
- [Call Stack](https://en.wikipedia.org/wiki/Call_stack)
- [Heap Allocation](https://os.phil-opp.com/heap-allocation/)
- [Allocator Designs](https://os.phil-opp.com/allocator-designs/)


<br>

---

# Footnotes

[^footnote]: is a stack data structure that stores information about the active subroutines of a computer program.
