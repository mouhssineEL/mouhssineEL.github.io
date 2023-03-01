---
title: Reversing | CrackMe Packed
author: Zeropio
date: 2023-03-01
categories: [CTFlike, Reversing]
tags: [reversing]
permalink: /ctf-like/reversing/crackme-packed
---

This challenge is from **Ricardo Narvaja**! You can download it [here](https://drive.google.com/file/d/1n93MT42C91fx-jV7wzKCvpeYXeD7Lss5/view). The objective is to find the real code execute inside the packer.

---

# Initial Analysis

Opening the PE in x32dbg show the following **EntryPoint**:

![](/assets/img/ctflike/reversing/2023-03-01_20-20.png)

It's a weird start that the executable start by `pushad`. In the **Memory Map** tab we can see the program start in the memory address **00401000**:

![](/assets/img/ctflike/reversing/2023-03-01_20-23.png)

That direction seems to be empty:

![](/assets/img/ctflike/reversing/2023-03-01_20-24.png)

Let's see if the PE works in the debugger. Running it should show the program:

![](/assets/img/ctflike/reversing/2023-03-01_20-29.png)

---

# Getting the Code

## With Breakpoints

Set a breakpoint to the first section after the header, the previous memory address **401000**:

![](/assets/img/ctflike/reversing/2023-03-01_20-31.png)

Run the program and wait. The program should stop at that memory address:

![](/assets/img/ctflike/reversing/2023-03-01_20-32.png)

As we can see, the previous empty direction is now full of instructions:

![](/assets/img/ctflike/reversing/2023-03-01_20-32_1.png)

## pushad popad Method

The program is pushing all the instructions to the stack in the EntryPoint, as we have seen. This means that in some point of the execution it will do a `popad`. So the moment the program call `popad`, it will be near the execution.

Press <kbd>F8</kbd> on the EntryPoint and <kbd>Follow in Dump</kbd> the **ESP**. Now select the ESP DWORD and set a hardware breakpoint on access.

![](/assets/img/ctflike/reversing/2023-03-01_20-38.png)

---

# Memory Dump

With the code in memory need to be dump. With the built-in plugin **Scylla** (<kbd>Ctrl</kbd> + <kbd>I</kbd>):

![](/assets/img/ctflike/reversing/2023-03-01_20-54.png)

Now we need to import the **IAT** (*Import Address Table*). Manually, we can follow the first function we found:

![](/assets/img/ctflike/reversing/2023-03-01_20-57.png)

Press <kbd>Enter</kbd> and <kbd>ollow in Dump</kbd>the **constant** the next indirect jump. Change the dump view to **Address**:

![](/assets/img/ctflike/reversing/2023-03-01_21-00.png)

To dump the IAT we need the **VA** and size. Select the first address of the IAT (at the top).

[](/assets/img/ctflike/reversing/2023-03-01_21-27.png)

For the size, double click on the first and scroll to the last one.

![](/assets/img/ctflike/reversing/2023-03-01_21-27_1.png)

We can set some extra bytes to make sure.

> We can use the button <kbd>IAT Autosearch</kbd>.

Now that the IAT is dumped it will look like:

![](/assets/img/ctflike/reversing/2023-03-01_21-30.png)

Make sure that everything work with <kbd>Show Invalid</kbd> and press <kbd>Fix Dump</kbd>. Select the dumped file.

---

# Dumped File

The first thing we can notice is that the EntryPoint has change to **401000**, where now all the unpacked program is:

![](/assets/img/ctflike/reversing/2023-03-01_21-33.png)


