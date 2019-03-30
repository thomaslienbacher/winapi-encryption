#include <stdio.h>
#include <stdint.h>
#include "crypto.h"

int main(int _argc, char *_argv[]) {
    LPTSTR *szArglist;
    int nArgs;

#ifdef UNICODE
    szArglist = CommandLineToArgvW(GetCommandLine(), &nArgs);
#else
    szArglist = _argv;
    nArgs = _argc;
#endif

    if (nArgs < 5) {
        _tprintf(TEXT("Usage: %s <key> <plaintext> <encrypted> <decrypted>\n"), szArglist[0]);
        _tprintf(TEXT("Use - to denote no file in <plaintext> <decrypted>\n"));
        return 1;
    }

    DWORD len = 0;
    BYTE *keyHash = hash(&len, szArglist[1], lstrlen(szArglist[1]) * sizeof(TCHAR));
    BYTE key[16] = {0};
    data_half_collapse(key, keyHash, len);

    LPTSTR plaintext = szArglist[2];
    LPTSTR encrypted = szArglist[3];
    LPTSTR decrypted = szArglist[4];

    if (_tcscmp(plaintext, TEXT("-")) != 0) {
        _tprintf(TEXT("Encrypting: %s => %s\n"), plaintext, encrypted);
        UCHAR gen[BLOCK_SIZE];
        secure_random(gen, BLOCK_SIZE);
        encrypt(plaintext, encrypted, key, gen);
    }

    if (_tcscmp(decrypted, TEXT("-")) != 0) {
        _tprintf(TEXT("Decrypting: %s => %s\n"), encrypted, decrypted);
        decrypt(encrypted, decrypted, key);
    }

    free(keyHash);

#ifdef UNICODE
    LocalFree(szArglist);
#endif

    return 0;
}