#include <stdarg.h>
#include <stdio.h>

static __printf(2, 3) void trace_emit(int lvl, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

void __attribute__((format(printf, 1, 2))) note(const char *msg, ...) {
	va_list args;
	va_start(args, msg);
	vprintf(msg, args);
	va_end(args);
}
