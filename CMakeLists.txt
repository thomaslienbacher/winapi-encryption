cmake_minimum_required(VERSION 3.13)
project(encryptor C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -march=native")

add_executable(encryptor main.c crypto.c crypto.h common.h aes.c)