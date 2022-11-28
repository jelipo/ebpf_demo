cmake_minimum_required(VERSION 3.24)
project(c C)

set(CMAKE_C_STANDARD 11)

# INCLUDE_DIRECTORIES(/lib/modules/5.15.68.1-microsoft-standard-WSL2/build/)

add_executable(c hello_kern.c)