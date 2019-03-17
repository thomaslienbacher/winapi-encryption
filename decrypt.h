//
// Created by Thomas on 16.03.2019.
//

#ifndef WINAPI_ENCRYPTION_DECRYPT_H
#define WINAPI_ENCRYPTION_DECRYPT_H

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include <stdbool.h>

bool MyDecryptFile(
        LPTSTR szSource,
        LPTSTR szDestination,
        LPTSTR szPassword);

int decrypt(int argc, _TCHAR *argv[]);

#endif //WINAPI_ENCRYPTION_DECRYPT_H
