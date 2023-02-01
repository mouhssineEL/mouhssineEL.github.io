---
title: Notes | Basic Reversing
author: Zeropio
date: 2023-01-29
categories: [Notes, Reversing]
tags: [reversing]
permalink: /notes/reversing/basic
---

We can use the following bash to send hex data as ASCII in a ELF binary:
```bash
#!/bin/bash
while read -r line; do echo -e $line; done | ./<BINARY>
```




