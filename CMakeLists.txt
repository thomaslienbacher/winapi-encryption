cmake_minimum_required(VERSION 3.13)
project(win_bcrypt_encryption C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -march=native")

add_executable(win_bcrypt_encryption main.c crypto.c crypto.h common.h)

target_link_libraries(win_bcrypt_encryption bcrypt)