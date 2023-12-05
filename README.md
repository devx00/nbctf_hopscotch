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

Normally, this function would subtract 0xd0 from the stack to make room, then it would stash all of its registers 
on the stack, then it would call `_dl_fixup`. 
When `_dl_fixup` returned it would then restore all of the registers from the stack and return.

By modifying the `_dl_runtime_resolve` address to point after the stack extension and register stashing code, I was 
able to make it restore registers from the previous stack location, which partially overlapped the input buffer which
my input was stored in. This allowed me to control many of the registers, including `x30` which is the return pointer. This will not be used immediately, but rather it will be used when the 
resolved function (printf in this case) returns. 

I also noticed during my exploit development that the stack always seemed to be allocated immediately after the executables 
mapped memory regions. This allowed me to determine where the input buffer was in memory and allowed me to have addresses which pointed into it loaded into registers. *Note: I am not sure if this was possible on the live challenge server. I never attempted this against the live server so it could possibly have been a quirk of how I was running it with qemu.*

