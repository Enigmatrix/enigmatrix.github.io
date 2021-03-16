---
title: DSO NUS 2021 CTF - SOAR (Reverse)
description: I really, really don't want to reverse this ;-;
date: 2021-03-16 10:55 PM UTC
tags:
  - ctf
  - dso-nus-ctf
  - rev
---

This challenge was a fun one since I did not really 'solve' it. I bruteforced my way through by using [Qiling](https://github.com/qilingframework/qiling).

We are handed a PDF File called `SOAR-challenge.pdf`. Opening it up, we see a advertisement for DSO (_organizers, that's a very smart way to do it!_), but nothing else very interesting. I thought it was unusual for a challenge to be in the **reversing** category but not offer anything to really reverse, so I peeked deeper into the file using `binwalk`, thinking that were probably embedded files in the pdf:
```sh
❯ binwalk SOAR-challenge.pdf

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PDF document, version: "1.4"
70            0x46            Zip archive data, at least v2.0 to extract, compressed size: 4729, uncompressed size: 4760, name: soar.zip
40792         0x9F58          End of Zip archive, footer length: 22
```

Extracing the files:
```
binwalk -e SOAR-challenge.pdf
```

The generated `_SOAR-challenge.pdf.extracted` folder has this structure:
```
> _SOAR-challenge.pdf.extracted
    > 46.zip
    > soar.zip
```
Opening up the `soar.zip` file, we see that it has one file inside, called `soar`. However, we cannot extract the file out as the zip is password protected. I threw the zip file into an [online zip password _recovery_ (ahem: **cracking**) service](https://www.lostmypass.com/), and got the `soar` file. The password was **dso**, very appropriate.

## Initial Analysis
Running the `soar` binary gives no output, so I opened up the file in [Ghidra]().

```c

// WARNING: Removing unreachable block (ram,0x00101c99)
// WARNING: Could not reconcile some variable overlaps

undefined8 main(void)

{
  
  bVar14 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_690 = (char *)malloc(0xd50c51);
  mem_i = 0;
  local_6b0 = 0;
  local_6a8 = 0;
  mem = malloc(0xd50c51);
  mem_i = 2;
  while ((long)mem_i < 0xd50c52) {
    *(undefined *)((long)mem + mem_i) = 1;
    mem_i = mem_i + 1;
  }
  mem_i = 2;
  while ((long)mem_i < 0xd50c52) {
    if (*(char *)((long)mem + mem_i) != '\0') {
      local_6b0 = mem_i * mem_i;
      while ((long)local_6b0 < 0xd50c51) {
        *(undefined *)((long)mem + local_6b0) = 0;
        local_6b0 = local_6b0 + mem_i;
      }
    }
    mem_i = mem_i + 1;
  }
  time(&local_6c0);
  CURRENT_TIME = localtime(&local_6c0);
  uVar9 = CURRENT_TIME->tm_min;
  buffer[0] = 0x36;
  buffer[1] = 0x26;
  buffer[2] = 0x18;
  buffer[3] = 0xb;
  buffer[4] = 0x24;
  buffer[5] = 0x11;
  buffer[6] = 0x12;
  buffer[7] = 0x10;
  buffer[8] = 0x1f;
  buffer[9] = 0x28;
  buffer[10] = 0x20;
  buffer[11] = 0x33;
  buffer[12] = 0x23;
  buffer[13] = 0x1e;
  buffer[14] = 0x16;
  buffer[15] = 0x2f;
  buffer[16] = 0x37;
  buffer[17] = 0xd;
  buffer[18] = 0x25;
  buffer[19] = 0x2c;
  buffer[20] = 0x21;
  buffer[21] = 0x14;
  buffer[22] = 0x15;
  buffer[23] = 0xc;
  buffer[24] = 0x1a;
  buffer[25] = 0x30;
  buffer[26] = 0x1c;
  buffer[27] = 0x1d;
  buffer[28] = 0xe;
  buffer[29] = 0x19;
  buffer[30] = 0x2e;
  buffer[31] = 0x17;
  buffer[32] = 0x31;
  buffer[33] = 0x34;
  buffer[34] = 0x29;
  buffer[35] = 0x39;
  buffer[36] = 0x13;
  buffer[37] = 0x32;
  buffer[38] = 0x2a;
  buffer[39] = 0x2d;
  buffer[40] = 0x35;
  buffer[41] = 0x38;
  buffer[42] = 0x1b;
  buffer[43] = 0x2b;
  buffer[44] = 0x27;
  buffer[45] = 0x22;
  buffer[46] = 0xf;
  local_5ac = 5;
  lVar8 = 0x30;
  plVar10 = &DAT_00102040;
  plVar12 = local_398;
  while (lVar8 != 0) {
    lVar8 = lVar8 + -1;
    *plVar12 = *plVar10;
    plVar10 = plVar10 + (ulong)bVar14 * -2 + 1;
    plVar12 = plVar12 + (ulong)bVar14 * -2 + 1;
  }
  local_690[0x2f] = '\0';
  mem_i = 0;
  while ((long)mem_i < 0x2f) {
    local_398[mem_i] = local_398[mem_i] + -0x1a000;
    local_398[mem_i] = local_398[mem_i] + -0xc51;
    local_398[mem_i] = local_398[mem_i] - (long)(int)((int)local_220 + 5U ^ uVar9);
    local_690[buffer[mem_i] - ((int)local_220 + 5)] = (char)local_398[mem_i];
    mem_i = mem_i + 1;
  }
  mem_i = 0;
  local_678 = fopen(local_690,"r");
  if (local_678 != NULL) {
    fseek(local_678,0,SEEK_END);
    lVar8 = ftell(local_678);
    mem_i = (ulong)(lVar8 == (int)((local_5ac + (int)local_220 ^ uVar9) + 0x18ce6));
    fclose(local_678);
  }
  iVar2 = CURRENT_TIME->tm_hour;
  if (mem_i != 0) {
    local_6a0 = 0;
    while (local_6a0 < 0xd50c51) {
      if (*(char *)((long)mem + local_6a0) != '\0') {
        local_670 = malloc(0x2a);
        lVar8 = local_6a0;
        local_6cc = (int)local_6a0;
        local_6b0 = 0;
        lVar4 = local_6b0;
        do {
          local_6b0 = lVar4;
          bVar3 = (byte)(local_6cc >> 0x37);
          uVar9 = (uint)(local_6cc >> 0x1f) >> 0x1c;
          if ((int)((local_6cc + uVar9 & 0xf) - uVar9) < 10) {
            cVar5 = '0';
          }
          else {
            cVar5 = 'W';
          }
          *(byte *)((long)local_670 + local_6b0) =
               (((char)local_6cc + (bVar3 >> 4) & 0xf) - (bVar3 >> 4)) + cVar5;
          if (local_6cc < 0) {
            local_6cc = local_6cc + 0xf;
          }
          local_6cc = local_6cc >> 4;
          lVar4 = local_6b0 + 1;
        } while (local_6cc != 0);
        iVar6 = (int)local_6b0;
        *(undefined *)((long)local_670 + local_6b0 + 1) = 0;
        local_6a0 = 0;
        local_6b0 = SEXT48(iVar6);
        while (local_6a0 < (long)local_6b0) {
          uVar1 = *(undefined *)((long)local_670 + local_6a0);
          *(undefined *)((long)local_670 + local_6a0) = *(undefined *)((long)local_670 +local_6b0);
          *(undefined *)((long)local_670 + local_6b0) = uVar1;
          local_6a0 = local_6a0 + 1;
          local_6b0 = local_6b0 - 1;
        }
        local_698 = 0;
        while (local_698 < iVar6 + 1) {
          local_690[local_6a8] = *(char *)(local_698 + (long)local_670);
          local_698 = local_698 + 1;
          local_6a8 = local_6a8 + 1;
        }
        local_690[local_6a8] = local_690[local_6a8] + 'C';
        local_690[local_6a8 + 1] = local_690[local_6a8 + 1];
        local_690[local_6a8 + 2] = local_690[local_6a8 + 2] + 'L';
        local_690[local_6a8 + 1] = 'S';
        local_6a8 = local_6a8 + 3;
        local_6a0 = lVar8;
        free(local_670);
      }
      local_6a0 = local_6a0 + 1;
    }
  }
  lVar8 = 0x41;
  plVar10 = &DAT_001021c0;
  plVar12 = local_218;
  while (lVar8 != 0) {
    lVar8 = lVar8 + -1;
    *plVar12 = *plVar10;
    plVar10 = plVar10 + (ulong)bVar14 * -2 + 1;
    plVar12 = plVar12 + (ulong)bVar14 * -2 + 1;
  }
  lVar8 = 0x20;
  puVar11 = &DAT_001023e0;
  puVar13 = local_4a8;
  while (lVar8 != 0) {
    lVar8 = lVar8 + -1;
    *puVar13 = *puVar11;
    puVar11 = puVar11 + (ulong)bVar14 * -2 + 1;
    puVar13 = puVar13 + (ulong)bVar14 * -2 + 1;
  }
  *(undefined4 *)puVar13 = *(undefined4 *)puVar11;
  mem_i = 0;
  while (mem_i < 0x40) {
    if (*(int *)((long)local_4a8 + mem_i * 4) - iVar2 < 1) {
      iVar6 = iVar2 - *(int *)((long)local_4a8 + mem_i * 4);
    }
    else {
      iVar6 = *(int *)((long)local_4a8 + mem_i * 4) - iVar2;
    }
    if (*(int *)((long)local_4a8 + mem_i * 4) - iVar2 < 1) {
      iVar7 = iVar2 - *(int *)((long)local_4a8 + mem_i * 4);
    }
    else {
      iVar7 = *(int *)((long)local_4a8 + mem_i * 4) - iVar2;
    }
    aiStack1448[(ulong)(long)iVar7 % 0x41] = (int)local_690[local_218[(ulong)(long)iVar6 %0x41]];
    mem_i = mem_i + 1;
  }
  mem_i = 0;
  while (mem_i < 0x40) {
    if ((mem_i & 1) == 0) {
      local_690[mem_i] = (char)aiStack1448[mem_i];
      if (mem_i == 0) {
        local_6b0 = mem_i;
      }
    }
    else {
      if ((iVar2 == local_3a8 + (int)local_18) &&
         (local_690[mem_i] = (char)aiStack1448[mem_i], mem_i == 1)) {
        local_6b0 = local_6b0 + 3;
      }
    }
    mem_i = mem_i + 1;
  }
  local_690[mem_i] = '\0';
  printf(*(char **)(fStr + local_6b0 * 8),local_690,local_690);
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}
```

Well, that's a lot of code. I was playing in this competition solo, so I was too lazy to properly reverse it at that time. Instead, I wrote a script that would solve it in the background for me, while I worked on other challenges in the foreground. But, to even write a script to bruteforce our way though, we need to find out what is variable (modifiable by us here), as it looks like this program takes no input.

## Looking a bit deeper
The program takes in the current time via
```c
  CURRENT_TIME = localtime(&local_6c0);
```
but only uses the `tm_min` and `tm_hour` fields
```c
  uVar9 = CURRENT_TIME->tm_min;
  ...
  iVar2 = CURRENT_TIME->tm_hour;
```

Furthermore, it opens a file, but only reads in it's file size, then compares it with another number. This number might be a derivative of `tm_min`, since the code before this uses `tm_min`, but we are not sure yet.

```c
  mem_i = 0;
  local_678 = fopen(local_690,"r"); // open file
  if (local_678 != NULL) {          // if exists...
    fseek(local_678,0,SEEK_END);    // seek to the end
    lVar8 = ftell(local_678);       // get the position of the current seek,
                                    // which is the end of the file,
                                    // effectively giving us the length of the file
    mem_i = (ulong)(lVar8 == (int)((local_5ac + (int)local_220 ^ uVar9) + 0x18ce6)); // compare it with this
    fclose(local_678);              // close back file
  }
  iVar2 = CURRENT_TIME->tm_hour;
  if (mem_i != 0) {                 // mem_i is either 0 or non-zero here
                                    // after this comparison, mem_i is overwritten
  ...
```

In the end, a printf-formatted string is printed out. We can surmise that `local_690` is a char array, since the end has a null byte, and thus that the format string has a `%s` format specifier.

```c
  local_690[mem_i] = '\0';
  printf(*(char **)(fStr + local_6b0 * 8),local_690,local_690);
```

So our variables are: the `tm_min` and `tm_hour` fields of the `tm` struct returned by `localtime()`, and the size of a file (that we do not know the name of).


## Solution

We have to iterate through all possible `tm_min` (0-60) and `tm_hour` (0-24) values.

As for the file, we don't even need to know it's name or file size! Note that the variables used, `lVar8` (size of file) and `local_678` (file pointer) are overwritten afterwards, and they only serve to set `mem_i` to either 0 or 1 (the result of the comparison with a number). We can set the value of `mem_i` when it is next used, the `if (mem_i != 0)`, to the value we want to try out. I assumed that we take the branch since the default was to avoid it (`mem_i` is set as 0 originally).

To put it simply, before `tm_min` and `tm_hour` are used, we have to set it to the values we want, and when comparing `mem_i` with 0 in the `if`, we have to set it to `1`. I used Qiling for this task, but there are alternatives as well, such as Frida and GDB Scripting. I did not even need to read the documentation much, as it was very user friendly. Skimming the home page of Qiling and its examples is sufficient.

```py
from qiling import *
from pwn import *

base = 0x555555554000 # base address of executable, loaded by Qiling when PIE is enabled

# These offsets can be found from the binary
printf = base + 0x01d48 
set_localtime = base + 0x139b
comparison = base + 0x174a

for h in range(0, 24):
    for m in range(0, 60):

        def get_output(ql: Qiling):
            fmt = ql.mem.string(ql.reg.RDI)
            inp1 = ql.mem.string(ql.reg.RSI)
            out = [(h,m), fmt, inp1]
            print(out)

        def set_localtime_fn(q: Qiling):
            tm = q.reg.RAX # output of localtime, the tm struct, is pointed by RAX
            q.mem.write(tm + 4, p32(m)) # &tm + 4 = tm_min
            q.mem.write(tm + 8, p32(h)) # &tm + 8 = tm_hour

        def set_comparison(q):
            mem_i = q.reg.RBP-0x6b0
            q.mem.write(mem_i, p32(1))

        q = Qiling(['./soar'], rootfs="/", console=False) # make it a bit less noisy when console=False

        q.hook_address(get_output, printf)
        q.hook_address(set_localtime_fn, set_localtime)
        q.hook_address(set_comparison, comparison) # hooks

        q.run() # wheee
```
The initial output is as follows:
```
[(0, 0), '\n', '']

[(0, 1), '\n', '']

[(0, 2), '\n', '']

[(0, 3), '\n', '']
...
```
After a long wait (while I was solving other challenges in the foreground :)), we see this:
```
...
[(10, 58), '\n', '']

[(10, 59), '\n', '']

[(11, 0), '%s\n', '4c7b655ed2e3eb42f1d886786c14fe5a757e416f5373de5cd2e4089b870eb5da']
4c7b655ed2e3eb42f1d886786c14fe5a757e416f5373de5cd2e4089b870eb5da
[(11, 1), '%s\n', '4c7b655ed2e3eb42f1d886786c14fe5a757e416f5373de5cd2e4089b870eb5da']
4c7b655ed2e3eb42f1d886786c14fe5a757e416f5373de5cd2e4089b870eb5da
...
```
Huzzah!

## Conclusion
This probably was not the intended solution, but I was short on time. Luckily the script needed very little debugging, and I managed to get valid outputs on my first few tries. Overall, I am quite amazed with Qiling and it's ability to isolate and emulate binaries, and even provide a high level of introspection.

I did manage to know what the 'intended' solution was, which was to download a file from DSO's site, [https://www.dso.org.sg/Media/Default/pdf/SOAR%20Insert.pdf](https://www.dso.org.sg/Media/Default/pdf/SOAR%20Insert.pdf) (this PDF is actually referenced in an unused function that I did not notice), which was the file that we checked the size for, then bruteforcing `tm_min` (`tm_hour` doesn't even matter!).

Or download the file, then wait for noon :joy: