//
// Created by Thomas on 16.03.2019.
//

#include <stdint.h>
#include "crypto.h"

void *hash(PDWORD hashSize, PBYTE src, ULONG length) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD cbData = 0,
            hashObjectSize = 0;
    PBYTE hashObject = NULL;
    PBYTE output = NULL;

    if (BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_SHA256_ALGORITHM,
            NULL,
            0)) {
        PrintError(TEXT("Error returned by BCryptOpenAlgorithmProvider\n"));
        goto hash_exit;
    }

    if (BCryptGetProperty(
            hAlg,
            BCRYPT_OBJECT_LENGTH,
            (PBYTE) &hashObjectSize,
            sizeof(DWORD),
            &cbData,
            0)) {
        PrintError(TEXT("**** Error 0x%x returned by BCryptGetProperty\n"));
        goto hash_exit;
    }

    hashObject = malloc(hashObjectSize);
    if (NULL == hashObject) {
        PrintError(TEXT("Memory allocation failed\n"));
        goto hash_exit;
    }

    if (BCryptGetProperty(
            hAlg,
            BCRYPT_HASH_LENGTH,
            hashSize,
            sizeof(DWORD),
            &cbData,
            0)) {
        PrintError(TEXT("**** Error 0x%x returned by BCryptGetProperty\n"));
        goto hash_exit;
    }

    output = malloc(*hashSize);
    if (NULL == output) {
        PrintError(TEXT("Memory allocation failed\n"));
        goto hash_exit;
    }

    if (BCryptCreateHash(
            hAlg,
            &hHash,
            hashObject,
            hashObjectSize,
            NULL,
            0,
            0)) {
        PrintError(TEXT("Error returned by BCryptCreateHash\n"));
        goto hash_exit;
    }

    if (BCryptHashData(
            hHash,
            src,
            length,
            0)) {
        PrintError(TEXT("Error returned by BCryptHashData\n"));
        goto hash_exit;
    }

    if (BCryptFinishHash(
            hHash,
            output,
            *hashSize,
            0)) {
        PrintError(TEXT("Error returned by BCryptFinishHash\n"));
        goto hash_exit;
    }

    hash_exit:

    if (hHash) {
        BCryptDestroyHash(hHash);
    }

    if (hashObject) {
        free(hashObject);
    }

    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    return output;
}

void data_half_collapse(PBYTE dst, PBYTE src, ULONG length) {
    ULONG iA = 0, iB = length / 2;

    for (; iB < length; iA++, iB++) {
        dst[iA] = src[iA] ^ src[iB];
    }
}

void secure_random(PBYTE dst, ULONG length) {
    BCRYPT_ALG_HANDLE hAlg = NULL;

    if (BCryptOpenAlgorithmProvider(
            &hAlg,
            BCRYPT_RNG_ALGORITHM,
            NULL,
            0)) {
        PrintError(TEXT("Error returned by BCryptOpenAlgorithmProvider\n"));
        goto sr_exit;
    }

    if (BCryptGenRandom(hAlg, dst, length, 0)) {
        PrintError(TEXT("Error returned by BCryptGenRandom\n"));
        goto sr_exit;
    }

    sr_exit:

    if (hAlg) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
}

int encrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, BYTE key[16], PBYTE iv) {
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

    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbCipherText = 0,
            cbData = 0,
            cbKeyObject = 0;
    PBYTE pbCipherText = NULL,
            pbKeyObject = NULL,
            ivBuffer = NULL;

    if (BCryptOpenAlgorithmProvider(
            &hAesAlg,
            BCRYPT_AES_ALGORITHM,
            NULL,
            0)) {
        PrintError(TEXT("Error returned by BCryptOpenAlgorithmProvider\n"));
        goto encrypt_exit;
    }

    if (BCryptGetProperty(
            hAesAlg,
            BCRYPT_OBJECT_LENGTH,
            (PBYTE) &cbKeyObject,
            sizeof(DWORD),
            &cbData,
            0)) {
        PrintError(TEXT("Error returned by BCryptGetProperty\n"));
        goto encrypt_exit;
    }

    pbKeyObject = malloc(cbKeyObject);
    if (NULL == pbKeyObject) {
        PrintError(TEXT("Memory allocation failed\n"));
        goto encrypt_exit;
    }

    ivBuffer = malloc(BLOCK_SIZE);
    if (NULL == ivBuffer) {
        PrintError(TEXT("Memory allocation failed\n"));
        goto encrypt_exit;
    }

    memcpy(ivBuffer, iv, BLOCK_SIZE);

    if (BCryptSetProperty(
            hAesAlg,
            BCRYPT_CHAINING_MODE,
            (PBYTE) BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0)) {
        PrintError(TEXT("Error returned by BCryptSetProperty\n"));
        goto encrypt_exit;
    }

    if (BCryptGenerateSymmetricKey(
            hAesAlg,
            &hKey,
            pbKeyObject,
            cbKeyObject,
            (PBYTE) key,
            BLOCK_SIZE,
            0)) {
        PrintError(TEXT("Error returned by BCryptGenerateSymmetricKey\n"));
        goto encrypt_exit;
    }

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

    if (!WriteFile(
            hDestinationFile,
            iv,
            BLOCK_SIZE,
            &bytesWritten,
            NULL)) {
        PrintError(TEXT("Error writing iv\n"));
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

        if (BCryptEncrypt(
                hKey,
                in,
                BLOCK_SIZE,
                NULL,
                ivBuffer,
                BLOCK_SIZE,
                NULL,
                0,
                &cbCipherText,
                0)) {
            PrintError(TEXT("Error returned by BCryptEncrypt\n"));
            goto encrypt_exit;
        }

        pbCipherText = malloc(cbCipherText);
        if (NULL == pbCipherText) {
            PrintError(TEXT("Memory allocation failed\n"));
            goto encrypt_exit;
        }

        if (BCryptEncrypt(
                hKey,
                in,
                BLOCK_SIZE,
                NULL,
                ivBuffer,
                BLOCK_SIZE,
                out,
                BLOCK_SIZE,
                &cbData,
                0)) {
            PrintError(TEXT("Error returned by BCryptEncrypt\n"));
            goto encrypt_exit;
        }

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

    if (hAesAlg) {
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }

    if (hKey) {
        BCryptDestroyKey(hKey);
    }

    if (pbCipherText) {
        free(pbCipherText);
    }

    if (pbKeyObject) {
        free(pbKeyObject);
    }

    if (ivBuffer) {
        free(ivBuffer);
    }

    return fReturn;
}

int decrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, BYTE key[16]) {
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

    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbCipherText = 0,
            cbData = 0,
            cbKeyObject = 0;
    PBYTE pbCipherText = NULL,
            pbKeyObject = NULL,
            ivBuffer = NULL;

    if (BCryptOpenAlgorithmProvider(
            &hAesAlg,
            BCRYPT_AES_ALGORITHM,
            NULL,
            0)) {
        PrintError(TEXT("Error returned by BCryptOpenAlgorithmProvider\n"));
        goto decrypt_exit;
    }

    if (BCryptGetProperty(
            hAesAlg,
            BCRYPT_OBJECT_LENGTH,
            (PBYTE) &cbKeyObject,
            sizeof(DWORD),
            &cbData,
            0)) {
        PrintError(TEXT("Error returned by BCryptGetProperty\n"));
        goto decrypt_exit;
    }

    pbKeyObject = malloc(cbKeyObject);
    if (NULL == pbKeyObject) {
        PrintError(TEXT("Memory allocation failed\n"));
        goto decrypt_exit;
    }

    if (BCryptSetProperty(
            hAesAlg,
            BCRYPT_CHAINING_MODE,
            (PBYTE) BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0)) {
        PrintError(TEXT("Error returned by BCryptSetProperty\n"));
        goto decrypt_exit;
    }

    if (BCryptGenerateSymmetricKey(
            hAesAlg,
            &hKey,
            pbKeyObject,
            cbKeyObject,
            (PBYTE) key,
            BLOCK_SIZE,
            0)) {
        PrintError(TEXT("Error returned by BCryptGenerateSymmetricKey\n"));
        goto decrypt_exit;
    }

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

    ivBuffer = malloc(BLOCK_SIZE);
    if (NULL == ivBuffer) {
        PrintError(TEXT("Memory allocation failed\n"));
        goto decrypt_exit;
    }

    if (!ReadFile(
            hSourceFile,
            ivBuffer,
            BLOCK_SIZE,
            &bytesRead,
            NULL)) {
        PrintError(TEXT("Error reading iv.\n"));
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

        if (BCryptDecrypt(
                hKey,
                in,
                BLOCK_SIZE,
                NULL,
                ivBuffer,
                BLOCK_SIZE,
                NULL,
                0,
                &cbCipherText,
                0)) {
            PrintError(TEXT("Error returned by BCryptDecrypt\n"));
            goto decrypt_exit;
        }

        pbCipherText = malloc(cbCipherText);
        if (NULL == pbCipherText) {
            PrintError(TEXT("Memory allocation failed\n"));
            goto decrypt_exit;
        }

        if (BCryptDecrypt(
                hKey,
                in,
                BLOCK_SIZE,
                NULL,
                ivBuffer,
                BLOCK_SIZE,
                out,
                BLOCK_SIZE,
                &cbData,
                0)) {
            PrintError(TEXT("Error returned by BCryptDecrypt\n"));
            goto decrypt_exit;
        }

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

    if (hAesAlg) {
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }

    if (hKey) {
        BCryptDestroyKey(hKey);
    }

    if (pbCipherText) {
        free(pbCipherText);
    }

    if (pbKeyObject) {
        free(pbKeyObject);
    }

    if (ivBuffer) {
        free(ivBuffer);
    }

    return fReturn;
}

