#ifndef COMPAT_H
#define COMPAT_H
~>#define NO_CRT_WARN __pragma(warning(disable: 4996))
~>#define NO_FMT_WARN _Pragma("GCC diagnostic ignored \"-Wformat-nonliteral\"")
#endif
