#include <sys/capability.h>

int grant(void)
{
    cap_t caps = cap_get_proc();
    cap_value_t wanted[] = { CAP_NET_ADMIN,
                             CAP_SYS_ADMIN };
~>    if (cap_set_flag(caps, CAP_EFFECTIVE, 2, wanted, CAP_SET) == -1)
        return -1;
~>    cap_set_flag(caps, CAP_PERMITTED, 2, wanted, CAP_SET);
    return cap_set_proc(caps);
}

int grant_inline(cap_t caps)
{
~>    return cap_set_flag(caps, CAP_INHERITABLE, 1, &(cap_value_t){CAP_SYS_PTRACE}, CAP_SET);
}
