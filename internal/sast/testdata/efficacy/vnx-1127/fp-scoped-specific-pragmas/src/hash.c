#include <stdint.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
uint32_t mix(uint32_t h, int n) {
    switch (n) {
    case 3: h ^= 3;
    case 2: h ^= 2;
    }
    return h;
}
#pragma GCC diagnostic pop

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127) /* conditional expression is constant */
#pragma warning(pop)
#endif
#pragma GCC diagnostic ignored "-Wuninitialized"
