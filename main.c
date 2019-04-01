#include <stdio.h>
#include "crypto.h"


void print_help(LPTSTR app) {
    _tprintf(TEXT("cngcrypt (built on "
                          __TIMESTAMP__
                          ")\n"
                          "Author: Thomas Lienbacher <lienbacher.tom@gmail.com>\n"
                          "Small file encryption CLI using the Windows CNG API and AES-128\n"
                          "\n"
                          "USAGE:\n"
                          "    %s [FLAGS] <SECRET> <INPUT> <OUTPUT>\n"
                          "\n"
                          "FLAGS:\n"
                          "    -e               Encrypt input file to output file\n"
                          "    -d               Decrypt input file to output file\n"
                          "    -S               Print derived AES key and IV\n"
                          "    -h               Prints help information and exits\n"
                          "\nEncryption and decryption are mutually exclusive\n"
                          "\n"),
             app);
}

char find_arg(LPTSTR *argv, int argc, LPTSTR arg) {
    for (int i = 0; i < argc; ++i) {
        if (_tcscmp(argv[i], arg) == 0) return 1;
    }

    return 0;
}

static inline void print_hex(unsigned char *data, int len) {
    for (int i = 0; i < len; ++i) {
        _tprintf(TEXT("%02x"), data[i]);
    }
}

int main(int _argc, char *_argv[]) {
    LPTSTR *szArglist;
    int nArgs;

#ifdef UNICODE
    szArglist = CommandLineToArgvW(GetCommandLine(), &nArgs);
#else
    szArglist = _argv;
    nArgs = _argc;
#endif

    if (nArgs < 2) {
        _tprintf(TEXT("Not enough arguments supplied!\n"
                      "Use -h to see help\n"));
        return 1;
    }

    char flagEncrypt = find_arg(szArglist + 1, nArgs - 1, TEXT("-e"));
    char flagDecrypt = find_arg(szArglist + 1, nArgs - 1, TEXT("-d"));
    char flagPrintKeys = find_arg(szArglist + 1, nArgs - 1, TEXT("-S"));
    char flagHelp = find_arg(szArglist + 1, nArgs - 1, TEXT("-h"));

    if (!(flagEncrypt || flagDecrypt || flagPrintKeys || flagHelp)) {
        _tprintf(TEXT("Wrong arguments supplied!\n"
                      "Use -h to see help\n"));
        return 1;
    }

    if (flagHelp) {
        print_help(szArglist[0]);
        return 1;
    }

    if (flagDecrypt && flagEncrypt) {
        _tprintf(TEXT("Can't encrypt and decrypt simultaneously!\n"
                      "Use -h to see help\n"));
        return 1;
    }

    DWORD len = 0;
    LPTSTR secret = szArglist[nArgs - 3];
    BYTE *keyHash = hash(&len, secret, lstrlen(secret) * sizeof(TCHAR));
    BYTE key[16] = {0};
    data_half_collapse(key, keyHash, len);

    LPTSTR input = szArglist[nArgs - 2];
    LPTSTR output = szArglist[nArgs - 1];

    //app flag S key input output
    if (flagEncrypt) {
        if (nArgs < (5 + flagPrintKeys)) {
            _tprintf(TEXT("Not enough arguments supplied!\n"
                          "Use -h to see help\n"));
            return 1;
        }

        UCHAR iv[BLOCK_SIZE];
        secure_random(iv, BLOCK_SIZE);

        if (flagPrintKeys) {
            _tprintf(TEXT("AES Key: "));
            print_hex(key, 16);
            _tprintf(TEXT("\nIV:      "));
            print_hex(iv, 16);
            _tprintf(TEXT("\n"));
        }

        _tprintf(TEXT("Encrypting: %s => %s\n"), input, output);
        encrypt(input, output, key, iv);
    }

    if (flagDecrypt) {
        if (nArgs < (5 + flagPrintKeys)) {
            _tprintf(TEXT("Not enough arguments supplied!\n"
                          "Use -h to see help\n"));
            return 1;
        }

        if (flagPrintKeys) {
            _tprintf(TEXT("AES Key:\t"));
            print_hex(key, 16);
            _tprintf(TEXT("\n"));
        }

        _tprintf(TEXT("Decrypting: %s => %s\n"), input, output);
        decrypt(input, output, key);
    }

    free(keyHash);

#ifdef UNICODE
    LocalFree(szArglist);
#endif

    return 0;
}