//
// Created by Thomas on 16.03.2019.
//

#ifndef WINAPI_ENCRYPTION_ENCRYPT_H
#define WINAPI_ENCRYPTION_ENCRYPT_H

#include "common.h"

#define BLOCK_SIZE 16

int encrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, uint8_t key[32]);

int decrypt(LPTSTR pszSourceFile, LPTSTR pszDestinationFile, uint8_t key[32]);


#endif //WINAPI_ENCRYPTION_ENCRYPT_H
