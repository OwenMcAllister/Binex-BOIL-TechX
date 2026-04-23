#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void vuln() {
    char buffer[64];
    
    puts("Read 1");
    read(0, buffer, 63);
    printf(buffer);
    
    puts("\nRead 2");
    read(0, buffer, 256); 
}

int main() {
    setup();
    vuln();
    puts("End of execution.");
    return 0;
}