cmake_minimum_required(VERSION 3.16)
project(netd C)

add_executable(netd src/main.c src/proto.c)
~>target_compile_options(netd PRIVATE -w)
