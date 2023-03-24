cmake_minimum_required(VERSION 3.22)
project(c C)

set(CMAKE_C_STANDARD 11)

include_directories(include)

add_executable(c
        hello/hello_kern.c
        hash_map/hash_map.c
        event_array/event_array.c
        ring_buffer/ring_buffer.c
        net/net.c cpudist/cpudist.c
        memory/memory.c
        kprobe/kprobe.c
        offcputime/offcputime.c
        )

