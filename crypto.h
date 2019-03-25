//
// Created by Thomas on 16.03.2019.
//

#ifndef WINAPI_ENCRYPTION_CRYPTO_H
#define WINAPI_ENCRYPTION_CRYPTO_H

#include "common.h"

#define BLOCK_SIZE 16

int encrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, uint8_t key[16],  uint8_t iv[16]);

int decrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, uint8_t key[16],  uint8_t iv[16]);


#endif //WINAPI_ENCRYPTION_CRYPTO_H
