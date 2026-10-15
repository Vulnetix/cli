#include <sys/capability.h>

int enable_mount(void) {
    cap_t caps = cap_get_proc();
    cap_value_t want = CAP_SYS_ADMIN;
~>    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &want, CAP_SET) == -1)
        return -1;
    return cap_set_proc(caps);
}
