cmake_minimum_required(VERSION 3.29)
project(pam C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(pam
        library.c
        library.h)
