/*
 * Ring buffer.
 */
#include <stddef.h>

static size_t head;   /* next write slot */
static size_t tail;   /* next read slot */

/* capacity must be a power of two */
#define CAP 1024
