#include <sys/socket.h>

#ifdef SO_REUSEPORT
static const bool kHasReusePort = true;
#else
static const bool kHasReusePort = false;
#endif

// we never call setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof one) here
const char *kNote = "SO_REUSEPORT is not enabled";
