//
// Created by Thomas on 16.03.2019.
//

#ifndef WINAPI_ENCRYPTION_CRYPTO_H
#define WINAPI_ENCRYPTION_CRYPTO_H

#include "common.h"

int encrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, uint8_t key[32]);

int decrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, uint8_t key[32]);


#endif //WINAPI_ENCRYPTION_CRYPTO_H
