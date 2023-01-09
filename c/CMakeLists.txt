cmake_minimum_required(VERSION 3.22)
project(c C)

set(CMAKE_C_STANDARD 11)


#execute_process(
#        COMMAND uname -r
#        OUTPUT_VARIABLE KERNEL_RELEASE
#        OUTPUT_STRIP_TRAILING_WHITESPACE
#)
#
#include_directories(/usr/src/linux-headers-${KERNEL_RELEASE}/include)


add_executable(c
        hello/hello_kern.c
        hash_map/hash_map.c
        event_array/event_array.c
        ring_buffer/ring_buffer.c
        net/net.c)