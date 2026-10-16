#include <sys/capability.h>

int allow_low_port(void)
{
    cap_value_t wanted[] = { CAP_NET_BIND_SERVICE };
    cap_t caps = cap_get_proc();
    cap_set_flag(caps, CAP_EFFECTIVE, 1, wanted, CAP_SET);
    int rc = cap_set_proc(caps);
    cap_free(caps);
    return rc;
}
