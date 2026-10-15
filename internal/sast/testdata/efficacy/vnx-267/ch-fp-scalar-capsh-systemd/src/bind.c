#include <sys/capability.h>

int enable_bind(void) {
    cap_t caps = cap_get_proc();
    cap_value_t want = CAP_NET_BIND_SERVICE;
    cap_value_t gone = CAP_SYS_ADMIN;
    cap_set_flag(caps, CAP_EFFECTIVE, 1, &want, CAP_SET);
    cap_set_flag(caps, CAP_PERMITTED, 1, &gone, CAP_CLEAR);
    return cap_set_proc(caps);
}
