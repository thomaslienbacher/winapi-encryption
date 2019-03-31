//
// Created by Thomas Lienbacher on 17.03.2019.
//

#ifndef WINAPI_ENCRYPTION_COMMON_H
#define WINAPI_ENCRYPTION_COMMON_H

#define UNICODE
#define _UNICODE

#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>
#include <conio.h>
#include <stdbool.h>

static void PrintError(LPTSTR errDesc) {
    fflush(stdout);
    LPVOID errMsg;

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER
                  | FORMAT_MESSAGE_FROM_SYSTEM
                  | FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL,
                  GetLastError(),
                  MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                  (LPTSTR) &errMsg,
                  0,
                  NULL);

    _ftprintf(stderr, TEXT("\nERROR %s: %s\n"), errDesc, (LPTSTR) errMsg);
    LocalFree((LPVOID) errMsg);
}

#endif //WINAPI_ENCRYPTION_COMMON_H
