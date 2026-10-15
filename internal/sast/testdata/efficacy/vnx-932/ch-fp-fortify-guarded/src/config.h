#pragma once
#if defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE > 0
#define HAVE_FORTIFY 1
#endif
#ifdef _FORTIFY_SOURCE
#undef _FORTIFY_SOURCE
#endif
#if defined(__OPTIMIZE__)
#define _FORTIFY_SOURCE 3
#endif
#pragma strict_gs_check(push, on)
