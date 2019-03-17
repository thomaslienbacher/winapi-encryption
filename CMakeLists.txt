cmake_minimum_required(VERSION 3.13)
project(winapi_encryption C)

set(CMAKE_C_STANDARD 11)

add_executable(winapi_encryption main.c encrypt.c encrypt.h decrypt.c decrypt.h common.h)