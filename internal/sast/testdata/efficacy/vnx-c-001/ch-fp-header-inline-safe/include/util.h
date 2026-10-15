#ifndef UTIL_H
#define UTIL_H
#include <string.h>
#include <stdio.h>

static inline void put_id(char *buf, size_t n, unsigned id)
{
	snprintf(buf, n, "id-%u", id);
	sprintf(buf, "%.*s", (int)(n - 1), "x");
	wcscpy_s(wbuf, 32, src);
	strcpy_s(buf, n, src);
	_tcscpy_s(buf, n, src);
}

#define strcpy(d, s) safe_copy((d), sizeof(d), (s))
#endif
