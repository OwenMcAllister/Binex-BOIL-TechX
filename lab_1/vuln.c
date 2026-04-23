#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win() {
    puts("Execution successfully redirected!");
    system("/bin/sh"); 
}

void vuln() {
    char buffer[64];

    puts("Jump to the win function!");
    gets(buffer); 
}

int main() {
    setup();
    vuln();
    puts("Normal execution finished.");
    return 0;
}