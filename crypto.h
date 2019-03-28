//
// Created by Thomas on 16.03.2019.
//

#ifndef WINAPI_ENCRYPTION_CRYPTO_H
#define WINAPI_ENCRYPTION_CRYPTO_H

#include "common.h"

#define BLOCK_SIZE 16

void *hash(PDWORD hashSize, PBYTE src, ULONG length);

void data_half_collapse(PBYTE dst, PBYTE src, ULONG length);

void secure_random(PBYTE dst, ULONG length);

int encrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, BYTE key[16], PBYTE iv);

int decrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, BYTE key[16]);


#endif //WINAPI_ENCRYPTION_CRYPTO_H
