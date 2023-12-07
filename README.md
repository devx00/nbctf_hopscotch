# NBCTF Hopscotch

## Description of Challenge
This was a 64bit ARM (aarch64) linux pwn challenge. 
The program began by printing the lines from /proc/self/maps that corresponded
to memory regions belonging to the main program elf but none of the library,stack,heap,etc regions.


The executable prompted us for 3 inputs: 
    1. (hex int) the exit status code to call exit with when complete.
    2. (hex int) an address
    3. (char) a value to write to that address.

The program would then write the first byte from the 3rd input to the address specified in the second
input. 
Next it would printf the string "Exiting with status %d" where %d is the status passed in the first input.
Finally it would call exit with the status from the first input.


## Summary of Exploit

The technique I went for was to tamper with the least significant byte of the `_dl_runtime_resolve` function 
pointer, which is present in the executables `.got.plt` section at runtime. 

```c
.got.plt (PROGBITS) section started  {0x21248-0x212c8}
00021248                          00 00 00 00 00 00 00 00          ........
00021250  00 00 00 00 00 00 00 00                          ........

00021258  int64_t runtime_resolve_ptr = 0x0 // <-- The _dl_runtime_resolve pointer will be here at runtime after linking.
00021260  void (* const exit)(int32_t status) __noreturn = exit
00021268  void (* const __libc_start_main)(int32_t (* main)(int32_t argc, char** argv, char** envp), int32_t argc, char** ubp_av, void (* init)(), void (* fini)(), void (* rtld_fini)(), void* stack_end) __noreturn = __libc_start_main
00021270  void (* const setbuf)(FILE* fp, char* buf) = setbuf
00021278  void (* const __cxa_finalize)(void* d) = __cxa_finalize
00021280  int32_t (* const open)(char const* file, int32_t oflag, ...) = open
00021288  int64_t (* const __gmon_start__)() = __gmon_start__
00021290  void (* const abort)() __noreturn = abort
00021298  int32_t (* const puts)(char const* str) = puts
000212a0  int64_t (* const strtol)(char const* nptr, char** endptr, int32_t base) = strtol
000212a8  int64_t (* const strchr)() = strchr
000212b0  ssize_t (* const read)(int32_t fd, void* buf, size_t nbytes) = read
000212b8  char* (* const strstr)(char const* haystack, char const* needle) = strstr
000212c0  int32_t (* const printf)(char const* format, ...) = printf
.got.plt (PROGBITS) section ended  {0x21248-0x212c8}

```

Normally, this function would subtract 0xd0 from the stack to make room, then it would stash all of its registers 
on the stack, then it would call `_dl_fixup`. 
When `_dl_fixup` returned it would then restore all of the registers from the stack and return.

Below is the disassembly of the `_dl_runtime_resolve` function.

```c
00012184  1f2003d5   nop     
00012188  e827b3a9   stp     x8, x9, [sp, #-0xd0]! {__saved_x8} {__saved_x9}
0001218c  e61f01a9   stp     x6, x7, [sp, #0x10] {__saved_x6} {__saved_x7}
00012190  e41702a9   stp     x4, x5, [sp, #0x20] {__saved_x4} {__saved_x5}
00012194  e20f03a9   stp     x2, x3, [sp, #0x30] {__saved_x2} {__saved_x3}
00012198  e00704a9   stp     x0, x1, [sp, #0x40] {__saved_x0} {__saved_x1}
0001219c  e08702ad   stp     q0, q1, [sp, #0x50] {__saved_v0} {__saved_v1}
000121a0  e28f03ad   stp     q2, q3, [sp, #0x70] {__saved_v2} {__saved_v3}
000121a4  e49704ad   stp     q4, q5, [sp, #0x90] {__saved_v4} {__saved_v5}
000121a8  e69f05ad   stp     q6, q7, [sp, #0xb0] {__saved_v6} {__saved_v7}
// We force it to skip everything above.
000121ac  00825ff8   ldur    x0, [x16, #-0x8]
000121b0  e16b40f9   ldr     x1, [sp, #0xd0 {arg2}]
000121b4  210010cb   sub     x1, x1, x16
000121b8  2104018b   add     x1, x1, x1, lsl #0x1
000121bc  21f07dd3   lsl     x1, x1, #0x3
000121c0  210003d1   sub     x1, x1, #0xc0
000121c4  21fc43d3   lsr     x1, x1, #0x3
000121c8  72f7ff97   bl      sub_ff90
000121cc  f00300aa   mov     x16, x0
000121d0  e08742ad   ldp     q0, q1, [sp, #0x50] {__saved_v0} {__saved_v1}
000121d4  e28f43ad   ldp     q2, q3, [sp, #0x70] {__saved_v2} {__saved_v3}
000121d8  e49744ad   ldp     q4, q5, [sp, #0x90] {__saved_v4} {__saved_v5}
000121dc  e69f45ad   ldp     q6, q7, [sp, #0xb0] {__saved_v6} {__saved_v7}
000121e0  e00744a9   ldp     x0, x1, [sp, #0x40] {__saved_x0} {__saved_x1}
000121e4  e20f43a9   ldp     x2, x3, [sp, #0x30] {__saved_x2} {__saved_x3}
000121e8  e41742a9   ldp     x4, x5, [sp, #0x20] {__saved_x4} {__saved_x5}
000121ec  e61f41a9   ldp     x6, x7, [sp, #0x10] {__saved_x6} {__saved_x7}
000121f0  e827cda8   ldp     x8, x9, [sp], #0xd0 {__saved_x8} {__saved_x9}
000121f4  f17bc1a8   ldp     x17, x30, [sp], #0x10 {arg2} {arg3}
000121f8  00021fd6   br      x16

```

By modifying the `_dl_runtime_resolve` address to point after the stack extension and register stashing code,
the first 10 lines of the disassembly above, I was able to make it restore registers from the previous stack 
location, which partially overlapped the input buffer which my input was stored in. This allowed me to control
many of the registers, including `x30` which is the return pointer. This will not be used immediately, but rather 
it will be used when the resolved function (printf in this case) returns. 

I used the call to printf to leak the GOT address of puts, which allowed me to rebase libc, and I used the x30 hijack
to return execution to the main function just after the check of the variable `bad_pwner_returning_to_main`. I then proceeded
to go through the same steps as the first time through except this time I replaced the GOT address of `printf` with the GOT address
of `strstr` which will cause it to resolve, and call, `strstr` instead. I did this so that I could take advantage of the fact that it 
returns an address if it finds the `needle` (arg2/x1) in the `haystack` (arg1/x0). By passing the address of the string `/bin/sh` found
in `libc` as both the needle and the haystack arguments, I could ensure that it would return the address of `/bin/sh` in `x0`. 

Finally, I made it call `system` by coercing the address of `libc.system` into `x30` and since the address of `/bin/sh` would be present in `x0` 
thanks to the call to `strstr`, I was given a shell.

