#include <sys/capability.h>

int bind_low_port(void)
{
    cap_t caps = cap_get_proc();
    cap_value_t keep[] = { CAP_NET_BIND_SERVICE };
    cap_set_flag(caps, CAP_EFFECTIVE, 1, keep, CAP_SET);
    cap_t ping = cap_from_text("cap_net_raw+ep");
    cap_free(ping);
    return cap_set_proc(caps);
}

int lower_admin(cap_t caps)
{
    cap_value_t admin[] = { CAP_SYS_ADMIN };
    return cap_set_flag(caps, CAP_EFFECTIVE, 1, admin, CAP_CLEAR);
}
