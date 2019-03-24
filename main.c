#include <stdio.h>
#include <stdint.h>
#include "crypto.h"

int main(int argc, char *argv[]) {
    uint32_t key[] = {
            0xd8bddad0,
            0x0191fb88,
            0x2c838aad,
            0x347beec3,
            0xbbe2060f,
            0x747a61eb,
            0xd9bfa0bd,
            0xd85f0f74
    };

    if (argc < 3)
        return 1;

    encrypt(argv[1], argv[2], (uint8_t *) key);

    return 0;
}