#include <stdio.h>
#include <stdint.h>
#include "crypto.h"

int main(int _argc, char *_argv[]) {
    uint8_t key[] = {
            0x7d, 0x1a, 0x61, 0x3c,
            0x1f, 0x3e, 0x45, 0x2d,
            0x55, 0xc1, 0x98, 0xe5,
            0x29, 0x2b, 0x06, 0x7a
    };

    UCHAR gen[BLOCK_SIZE];
    secure_random(gen, BLOCK_SIZE);

    LPTSTR *szArglist;
    int nArgs;

#ifdef UNICODE
    szArglist = CommandLineToArgvW(GetCommandLine(), &nArgs);
#else
    szArglist = _argv;
    nArgs = _argc;
#endif
    if (nArgs < 4) {
        _tprintf(TEXT("Usage: %s <input> <encrypted> <decrypted>\n"), szArglist[0]);
        _tprintf(TEXT("Use - to denote no file in <encrypted> <decrypted>\n"));
        return 1;
    }

    if (_tcscmp(szArglist[1], TEXT("-")) != 0 && _tcscmp(szArglist[2], TEXT("-")) != 0) {
        _tprintf(TEXT("Encrypting: %s => %s\n"), szArglist[1], szArglist[2]);
        encrypt(szArglist[1], szArglist[2], key, gen);
    }

    if (_tcscmp(szArglist[2], TEXT("-")) != 0 && _tcscmp(szArglist[3], TEXT("-")) != 0) {
        _tprintf(TEXT("Decrypting: %s => %s\n"), szArglist[2], szArglist[3]);
        decrypt(szArglist[2], szArglist[3], key);
    }

#ifdef UNICODE
    LocalFree(szArglist);
#endif

    return 0;
}