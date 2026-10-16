#include <sys/prctl.h>
#include <linux/capability.h>
#include <stdexcept>

void raise_for_child()
{
~>    if (::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_MODULE, 0, 0) != 0) {
        throw std::runtime_error("ambient raise failed");
    }
}
