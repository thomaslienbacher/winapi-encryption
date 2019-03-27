#include <stdio.h>
#include <stdint.h>
#include "crypto.h"

int main(int argc, char *argv[]) {
    uint8_t key[] = {
            0x7d, 0x1a, 0x61, 0x3c,
            0x1f, 0x3e, 0x45, 0x2d,
            0x55, 0xc1, 0x98, 0xe5,
            0x29, 0x2b, 0x06, 0x7a
    };

    UCHAR gen[BLOCK_SIZE];
    secure_random(gen, BLOCK_SIZE);

    if (argc < 4) {
        printf("Usage: %s <input> <encrypted> <decrypted>\n", argv[0]);
        puts("Use - to denote no file in <encrypted> <decrypted>");
        return 1;
    }

    if (strcmp(argv[1], "-") != 0 && strcmp(argv[2], "-") != 0) {
        printf("Encrypting: %s => %s\n", argv[1], argv[2]);
        encrypt(argv[1], argv[2], key, gen);
    }

    if (strcmp(argv[2], "-") != 0 && strcmp(argv[3], "-") != 0) {
        printf("Decrypting: %s => %s\n", argv[2], argv[3]);
        decrypt(argv[2], argv[3], key);
    }

    return 0;
}