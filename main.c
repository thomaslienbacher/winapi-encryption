#include <stdio.h>
#include "encrypt.h"
#include "decrypt.h"

int main(int argc, char *argv[]) {
    char *a[] = {"this", "test.txt", "test.enc", "key123"};
    char *b[] = {"this", "test.enc", "test.dec", "key123"};
    encrypt(4, a);

    puts("\n-\n");
    Sleep(3000);

    decrypt(4, b);
    return 0;
}