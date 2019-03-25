#include <stdio.h>
#include <stdint.h>
#include "crypto.h"

int main(int argc, char *argv[]) {
    uint32_t key[] = {
            0xd8bddad0,
            0x0191fb88,
            0x2c838aad,
            0x347beec3
    };

    if (argc < 4)
        return 1;

    encrypt(argv[1], argv[2], (uint8_t *) key);
    decrypt(argv[2], argv[3], (uint8_t *) key);

    return 0;
}