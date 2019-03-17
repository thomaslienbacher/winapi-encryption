//
// Created by Thomas on 16.03.2019.
//

#ifndef WINAPI_ENCRYPTION_ENCRYPT_H
#define WINAPI_ENCRYPTION_ENCRYPT_H

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include <stdbool.h>


bool MyEncryptFile(
        LPTSTR szSource,
        LPTSTR szDestination,
        LPTSTR szPassword);

int encrypt(int argc, _TCHAR *argv[]);


#endif //WINAPI_ENCRYPTION_ENCRYPT_H
