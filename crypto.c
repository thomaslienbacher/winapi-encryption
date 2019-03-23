//
// Created by Thomas on 16.03.2019.
//

#include <stdint.h>
#include "crypto.h"
#include "aes.h"

int encrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, uint8_t key[32]) {
    bool fReturn = false;
    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;

    hSourceFile = CreateFile(
            pszSourceFile,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    if (hSourceFile == INVALID_HANDLE_VALUE) {
        PrintError(TEXT("Error opening source plaintext file!\n"));
        goto encrypt_exit;
    }

    hDestinationFile = CreateFile(
            pszDestinationFile,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    if (hDestinationFile == INVALID_HANDLE_VALUE) {
        PrintError(TEXT("Error opening destination file!\n"));
        goto encrypt_exit;
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
        PrintError(TEXT("Error writing fileSize\n"));
        goto encrypt_exit;
    }

    bool fEOF;

    do {
        memset(in, 0, BLOCK_SIZE);
        memset(out, 0, BLOCK_SIZE);

        if (!ReadFile(
                hSourceFile,
                in,
                BLOCK_SIZE,
                &bytesRead,
                NULL)) {
            PrintError(TEXT("Error reading plaintext!\n"));
            goto encrypt_exit;
        }

        if (!bytesRead) break;
        fEOF = bytesRead < BLOCK_SIZE;

        aes_cipher(in, out, expandedKey);

        if (!WriteFile(
                hDestinationFile,
                out,
                BLOCK_SIZE,
                &bytesWritten,
                NULL)) {
            PrintError(TEXT("Error writing ciphertext!\n"));
            goto encrypt_exit;
        }

    } while (!fEOF);

    fReturn = true;

    encrypt_exit:

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

    hSourceFile = CreateFile(
            pszSourceFile,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    if (hSourceFile == INVALID_HANDLE_VALUE) {
        PrintError(TEXT("Error opening source plaintext file!\n"));
        goto decrypt_exit;
    }

    hDestinationFile = CreateFile(
            pszDestinationFile,
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
    if (hDestinationFile == INVALID_HANDLE_VALUE) {
        PrintError(TEXT("Error opening destination file!\n"));
        goto decrypt_exit;
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
        PrintError(TEXT("Error reading fileSize.\n"));
        goto decrypt_exit;
    }

    bool fEOF;

    do {
        memset(in, 0, BLOCK_SIZE);
        memset(out, 0, BLOCK_SIZE);

        if (!ReadFile(
                hSourceFile,
                in,
                BLOCK_SIZE,
                &bytesRead,
                NULL)) {
            PrintError(TEXT("Error reading plaintext!\n"));
            goto decrypt_exit;
        }

        if (!bytesRead) break;
        fEOF = bytesRead < BLOCK_SIZE;

        aes_inv_cipher(in, out, expandedKey);

        DWORD bytesToWrite = (DWORD) (BLOCK_SIZE < fileSize.QuadPart - bytesWrittenAll ? BLOCK_SIZE :
                                      fileSize.QuadPart - bytesWrittenAll);

        if (!WriteFile(
                hDestinationFile,
                out,
                bytesToWrite,
                &bytesWritten,
                NULL)) {
            PrintError(TEXT("Error writing ciphertext.\n"));
            goto decrypt_exit;
        }

        bytesWrittenAll += bytesWritten;
    } while (!fEOF);

    fReturn = true;

    decrypt_exit:

    if (hSourceFile) {
        CloseHandle(hSourceFile);
    }

    if (hDestinationFile) {
        CloseHandle(hDestinationFile);
    }

    free(expandedKey);

    return fReturn;
}

