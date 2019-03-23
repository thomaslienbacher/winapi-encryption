//
// Created by Thomas Lienbacher on 17.03.2019.
//

#ifndef WINAPI_ENCRYPTION_COMMON_H
#define WINAPI_ENCRYPTION_COMMON_H

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#include <stdbool.h>

static void MyHandleError(LPTSTR psz, int nErrorNumber) {
    fflush(stdout);
    _ftprintf(stderr, TEXT("ERR: %s %x\n"), psz, nErrorNumber);
    LPVOID errMsg;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
                  | FORMAT_MESSAGE_FROM_SYSTEM
                  | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  nErrorNumber,
                  MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                  (LPTSTR) &errMsg,
                  0,
                  NULL);

    _ftprintf(stderr, TEXT("\n** ERROR **: %s\n"), (LPTSTR) errMsg);
}

#endif //WINAPI_ENCRYPTION_COMMON_H
