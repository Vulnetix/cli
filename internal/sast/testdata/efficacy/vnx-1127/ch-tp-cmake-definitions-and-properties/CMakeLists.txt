cmake_minimum_required(VERSION 3.16)
project(parser C)

add_library(parser src/parse.c src/lex.c)
add_library(legacy STATIC third/legacy.c)

if(MSVC)
~>  target_compile_definitions(parser PRIVATE _CRT_SECURE_NO_WARNINGS)
  add_compile_definitions(
~>    _CRT_SECURE_NO_DEPRECATE)
~>  add_compile_options(/wd4996)
endif()

~>set_target_properties(legacy PROPERTIES COMPILE_FLAGS "-w")
~>set_source_files_properties(src/lex.c PROPERTIES COMPILE_OPTIONS "-Wno-format-security")
target_compile_options(parser PRIVATE -Wall -Wextra)
