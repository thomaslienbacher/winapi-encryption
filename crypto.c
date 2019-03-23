//
// Created by Thomas on 16.03.2019.
//

#include <stdint.h>
#include "crypto.h"
#include "common.h"
#include "aes.h"

int encrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, uint8_t key[32]) {
    bool fReturn = false;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

    //---------------------------------------------------------------
    // Open the source file.
    hSourceFile = CreateFile(
            pszSourceFile,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    if (INVALID_HANDLE_VALUE != hSourceFile) {
        _tprintf(
                TEXT("The source plaintext file, %s, is open. \n"),
                pszSourceFile);
    } else {
        MyHandleError(
                TEXT("Error opening source plaintext file!\n"),
                GetLastError());
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // Open the destination file.
    hDestinationFile = CreateFile(
            pszDestinationFile,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    if (INVALID_HANDLE_VALUE != hDestinationFile) {
        _tprintf(
                TEXT("The destination file, %s, is open. \n"),
                pszDestinationFile);
    } else {
        MyHandleError(
                TEXT("Error opening destination file!\n"),
                GetLastError());
        goto Exit_MyEncryptFile;
    }

    uint8_t *expandedKey = aes_init(sizeof(uint8_t[32]));
    aes_key_expansion(key, expandedKey);

    uint8_t in[BLOCK_SIZE];
    uint8_t out[BLOCK_SIZE];
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;

    LARGE_INTEGER fileSize = {0};
    GetFileSizeEx(hSourceFile, &fileSize);

    if (!WriteFile(
            hDestinationFile,
            &fileSize.QuadPart,
            sizeof(fileSize.QuadPart),
            &bytesWritten,
            NULL)) {
        MyHandleError(
                TEXT("Error writing fileSize.\n"),
                GetLastError());
        goto Exit_MyEncryptFile;
    }
    _tprintf("%lu : %llu\n", bytesWritten, fileSize.QuadPart);

    bool fEOF = FALSE;

    do {
        memset(in, 0, BLOCK_SIZE);
        memset(out, 0, BLOCK_SIZE);

        //-----------------------------------------------------------
        // Read up to dwBlockLen bytes from the source file.
        if (!ReadFile(
                hSourceFile,
                in,
                BLOCK_SIZE,
                &bytesRead,
                NULL)) {
            MyHandleError(
                    TEXT("Error reading plaintext!\n"),
                    GetLastError());
            goto Exit_MyEncryptFile;
        }

        if (!bytesRead) break;

        if (bytesRead < BLOCK_SIZE) {
            fEOF = TRUE;
        }


        printf("Plaintext message:\n");
        for (int i = 0; i < 4; i++) {
            printf("%x %x %x %x\n", in[4 * i + 0], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
        }
        aes_cipher(in, out, expandedKey);
        printf("Ciphered message:\n");
        for (int i = 0; i < 4; i++) {
            printf("%x %x %x %x\n", out[4 * i + 0], out[4 * i + 1], out[4 * i + 2], out[4 * i + 3]);
        }

        //-----------------------------------------------------------
        // Write the encrypted data to the destination file.
        if (!WriteFile(
                hDestinationFile,
                out,
                BLOCK_SIZE,
                &bytesWritten,
                NULL)) {
            MyHandleError(
                    TEXT("Error writing ciphertext.\n"),
                    GetLastError());
            goto Exit_MyEncryptFile;
        }

        _tprintf("%lu => %lu\n", bytesRead, bytesWritten);
    } while (!fEOF);

    fReturn = true;

    Exit_MyEncryptFile:

    if (hSourceFile) {
        CloseHandle(hSourceFile);
    }

    if (hDestinationFile) {
        CloseHandle(hDestinationFile);
    }

    free(expandedKey);

    return fReturn;
}

int decrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, uint8_t key[32]) {
    bool fReturn = false;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

    //---------------------------------------------------------------
    // Open the source file.
    hSourceFile = CreateFile(
            pszSourceFile,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    if (INVALID_HANDLE_VALUE != hSourceFile) {
        _tprintf(
                TEXT("The source plaintext file, %s, is open. \n"),
                pszSourceFile);
    } else {
        MyHandleError(
                TEXT("Error opening source plaintext file!\n"),
                GetLastError());
        goto Exit_MyEncryptFile;
    }

    //---------------------------------------------------------------
    // Open the destination file.
    hDestinationFile = CreateFile(
            pszDestinationFile,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    if (INVALID_HANDLE_VALUE != hDestinationFile) {
        _tprintf(
                TEXT("The destination file, %s, is open. \n"),
                pszDestinationFile);
    } else {
        MyHandleError(
                TEXT("Error opening destination file!\n"),
                GetLastError());
        goto Exit_MyEncryptFile;
    }


    uint8_t *expandedKey = aes_init(sizeof(uint8_t[32]));
    aes_key_expansion(key, expandedKey);

    uint8_t in[BLOCK_SIZE];
    uint8_t out[BLOCK_SIZE];
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    DWORD bytesWrittenAll = 0;

    LARGE_INTEGER fileSize = {0};

    if (!ReadFile(
            hSourceFile,
            &fileSize.QuadPart,
            sizeof(fileSize.QuadPart),
            &bytesRead,
            NULL)) {
        MyHandleError(
                TEXT("Error reading fileSize.\n"),
                GetLastError());
        goto Exit_MyEncryptFile;
    }
    _tprintf("%lu : %llu\n", bytesRead, fileSize.QuadPart);

    bool fEOF = FALSE;

    do {
        memset(in, 0, BLOCK_SIZE);
        memset(out, 0, BLOCK_SIZE);

        //-----------------------------------------------------------
        // Read up to dwBlockLen bytes from the source file.
        if (!ReadFile(
                hSourceFile,
                in,
                BLOCK_SIZE,
                &bytesRead,
                NULL)) {
            MyHandleError(
                    TEXT("Error reading plaintext!\n"),
                    GetLastError());
            goto Exit_MyEncryptFile;
        }

        if (!bytesRead) break;

        if (bytesRead < BLOCK_SIZE) {
            fEOF = TRUE;
        }

        printf("Plaintext message:\n");
        for (int i = 0; i < 4; i++) {
            printf("%x %x %x %x\n", in[4 * i + 0], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
        }
        aes_inv_cipher(in, out, expandedKey);
        printf("Ciphered message:\n");
        for (int i = 0; i < 4; i++) {
            printf("%x %x %x %x\n", out[4 * i + 0], out[4 * i + 1], out[4 * i + 2], out[4 * i + 3]);
        }


        DWORD bytesToWrite = (DWORD) (BLOCK_SIZE < fileSize.QuadPart - bytesWrittenAll ? BLOCK_SIZE :
                                      fileSize.QuadPart - bytesWrittenAll);

        //-----------------------------------------------------------
        // Write the encrypted data to the destination file.
        if (!WriteFile(
                hDestinationFile,
                out,
                bytesToWrite,
                &bytesWritten,
                NULL)) {
            MyHandleError(
                    TEXT("Error writing ciphertext.\n"),
                    GetLastError());
            goto Exit_MyEncryptFile;
        }

        bytesWrittenAll += bytesWritten;
        _tprintf("%lu => %lu : %lu\n", bytesRead, bytesWritten, bytesWrittenAll);
    } while (!fEOF);

    fReturn = true;

    Exit_MyEncryptFile:

    if (hSourceFile) {
        CloseHandle(hSourceFile);
    }

    if (hDestinationFile) {
        CloseHandle(hDestinationFile);
    }

    free(expandedKey);

    return fReturn;
}

