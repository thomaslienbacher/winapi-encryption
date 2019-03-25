//
// Created by Thomas on 16.03.2019.
//

#include <stdint.h>
#include "crypto.h"

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

static const BYTE rgbIV[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

int encrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, uint8_t key[16]) {
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

    //*******************************
    //crypto init
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cbCipherText = 0,
            cbData = 0,
            cbKeyObject = 0;
    PBYTE pbCipherText = NULL,
            pbKeyObject = NULL,
            pbIV = NULL;

    // Open an algorithm handle.
    if ((status = BCryptOpenAlgorithmProvider(
            &hAesAlg,
            BCRYPT_AES_ALGORITHM,
            NULL,
            0))) {
        PrintError(TEXT("**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n"));
        goto encrypt_exit;
    }

    // Calculate the size of the buffer to hold the KeyObject.
    if ((status = BCryptGetProperty(
            hAesAlg,
            BCRYPT_OBJECT_LENGTH,
            (PBYTE) &cbKeyObject,
            sizeof(DWORD),
            &cbData,
            0))) {
        PrintError(TEXT("**** Error 0x%x returned by BCryptGetProperty\n"));
        goto encrypt_exit;
    }

    // Allocate the key object on the heap.
    pbKeyObject = (PBYTE) HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (NULL == pbKeyObject) {
        PrintError(TEXT("**** memory allocation failed\n"));
        goto encrypt_exit;
    }

    // Allocate a buffer for the IV. The buffer is consumed during the
    // encrypt/decrypt process.
    pbIV = (PBYTE) HeapAlloc(GetProcessHeap(), 0, BLOCK_SIZE);
    if (NULL == pbIV) {
        PrintError(TEXT("**** memory allocation failed\n"));
        goto encrypt_exit;
    }

    memcpy(pbIV, rgbIV, BLOCK_SIZE);

    if ((status = BCryptSetProperty(
            hAesAlg,
            BCRYPT_CHAINING_MODE,
            (PBYTE) BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0))) {
        PrintError(TEXT("**** Error 0x%x returned by BCryptSetProperty\n"));
        goto encrypt_exit;
    }

    // Generate the key from supplied input key bytes.
    if ((status = BCryptGenerateSymmetricKey(
            hAesAlg,
            &hKey,
            pbKeyObject,
            cbKeyObject,
            (PBYTE) key,
            BLOCK_SIZE,
            0))) {
        PrintError(TEXT("**** Error 0x%x returned by BCryptGenerateSymmetricKey\n"));
        goto encrypt_exit;
    }
    //*******************************

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

        //*******************************
        //encryption

        //
        // Get the output buffer size.
        //
        if ((status = BCryptEncrypt(
                hKey,
                in,
                BLOCK_SIZE,
                NULL,
                pbIV,
                BLOCK_SIZE,
                NULL,
                0,
                &cbCipherText,
                0))) {
            PrintError(TEXT("**** Error 0x%x returned by BCryptEncrypt\n"));
            goto encrypt_exit;
        }

        pbCipherText = (PBYTE) HeapAlloc(GetProcessHeap(), 0, cbCipherText);
        if (NULL == pbCipherText) {
            PrintError(TEXT("**** memory allocation failed\n"));
            goto encrypt_exit;
        }

        // Use the key to encrypt the plaintext buffer.
        // For block sized messages, block padding will add an extra block.
        if ((status = BCryptEncrypt(
                hKey,
                in,
                BLOCK_SIZE,
                NULL,
                pbIV,
                BLOCK_SIZE,
                out,
                BLOCK_SIZE,
                &cbData,
                0))) {
            PrintError(TEXT("**** Error 0x%x returned by BCryptEncrypt\n"));
            goto encrypt_exit;
        }
        //*******************************

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

    //*******************************
    //crypto close
    if (hAesAlg) {
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }

    if (hKey) {
        BCryptDestroyKey(hKey);
    }

    if (pbCipherText) {
        HeapFree(GetProcessHeap(), 0, pbCipherText);
    }

    if (pbKeyObject) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }

    if (pbIV) {
        HeapFree(GetProcessHeap(), 0, pbIV);
    }
    //*******************************

    return fReturn;
}

int decrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, uint8_t key[16]) {
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

    //*******************************
    //crypto init
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    DWORD cbCipherText = 0,
            cbData = 0,
            cbKeyObject = 0;
    PBYTE pbCipherText = NULL,
            pbKeyObject = NULL,
            pbIV = NULL;

    // Open an algorithm handle.
    if ((status = BCryptOpenAlgorithmProvider(
            &hAesAlg,
            BCRYPT_AES_ALGORITHM,
            NULL,
            0))) {
        PrintError(TEXT("**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n"));
        goto decrypt_exit;
    }

    // Calculate the size of the buffer to hold the KeyObject.
    if ((status = BCryptGetProperty(
            hAesAlg,
            BCRYPT_OBJECT_LENGTH,
            (PBYTE) &cbKeyObject,
            sizeof(DWORD),
            &cbData,
            0))) {
        PrintError(TEXT("**** Error 0x%x returned by BCryptGetProperty\n"));
        goto decrypt_exit;
    }

    // Allocate the key object on the heap.
    pbKeyObject = (PBYTE) HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (NULL == pbKeyObject) {
        PrintError(TEXT("**** memory allocation failed\n"));
        goto decrypt_exit;
    }

    // Allocate a buffer for the IV. The buffer is consumed during the
    // encrypt/decrypt process.
    pbIV = (PBYTE) HeapAlloc(GetProcessHeap(), 0, BLOCK_SIZE);
    if (NULL == pbIV) {
        PrintError(TEXT("**** memory allocation failed\n"));
        goto decrypt_exit;
    }

    memcpy(pbIV, rgbIV, BLOCK_SIZE);

    if ((status = BCryptSetProperty(
            hAesAlg,
            BCRYPT_CHAINING_MODE,
            (PBYTE) BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC),
            0))) {
        PrintError(TEXT("**** Error 0x%x returned by BCryptSetProperty\n"));
        goto decrypt_exit;
    }

    // Generate the key from supplied input key bytes.
    if ((status = BCryptGenerateSymmetricKey(
            hAesAlg,
            &hKey,
            pbKeyObject,
            cbKeyObject,
            (PBYTE) key,
            BLOCK_SIZE,
            0))) {
        PrintError(TEXT("**** Error 0x%x returned by BCryptGenerateSymmetricKey\n"));
        goto decrypt_exit;
    }

    //*******************************

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

        //*******************************
        //decryption

//
        // Get the output buffer size.
        //
        if ((status = BCryptDecrypt(
                hKey,
                in,
                BLOCK_SIZE,
                NULL,
                pbIV,
                BLOCK_SIZE,
                NULL,
                0,
                &cbCipherText,
                0))) {
            PrintError(TEXT("**** Error 0x%x returned by BCryptDecrypt\n"));
            goto decrypt_exit;
        }

        pbCipherText = (PBYTE) HeapAlloc(GetProcessHeap(), 0, cbCipherText);
        if (NULL == pbCipherText) {
            PrintError(TEXT("**** memory allocation failed\n"));
            goto decrypt_exit;
        }

        // Use the key to encrypt the plaintext buffer.
        // For block sized messages, block padding will add an extra block.
        if ((status = BCryptDecrypt(
                hKey,
                in,
                BLOCK_SIZE,
                NULL,
                pbIV,
                BLOCK_SIZE,
                out,
                BLOCK_SIZE,
                &cbData,
                0))) {
            PrintError(TEXT("**** Error 0x%x returned by BCryptDecrypt\n"));
            goto decrypt_exit;
        }

        //*******************************

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

    //*******************************
    //crypto close
    if (hAesAlg) {
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }

    if (hKey) {
        BCryptDestroyKey(hKey);
    }

    if (pbCipherText) {
        HeapFree(GetProcessHeap(), 0, pbCipherText);
    }

    if (pbKeyObject) {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }

    if (pbIV) {
        HeapFree(GetProcessHeap(), 0, pbIV);
    }
    //*******************************

    return fReturn;
}

