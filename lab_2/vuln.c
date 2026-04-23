#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void vuln() {
    char buffer[128];
    printf("Enter your input: ");
    read(0, buffer, 256);
}

int main() {
    setup();
    vuln();
    puts("Exiting program...");
    return 0;
}