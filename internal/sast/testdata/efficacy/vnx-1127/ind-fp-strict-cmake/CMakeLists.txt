cmake_minimum_required(VERSION 3.16)
project(strict CXX)
add_executable(strict main.cpp)
target_compile_options(strict PRIVATE -Wall -Wextra -Werror)
# never use -w or /W0 here
