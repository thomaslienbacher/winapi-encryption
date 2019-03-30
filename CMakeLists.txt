cmake_minimum_required(VERSION 3.13)
project(cngcrypt C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -march=native -Wall")

add_executable(cngcrypt main.c crypto.c crypto.h common.h)

target_link_libraries(cngcrypt bcrypt)