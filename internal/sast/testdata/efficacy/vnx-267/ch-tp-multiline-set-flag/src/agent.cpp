#include <sys/capability.h>

static bool raise_caps()
{
    cap_value_t wanted[] = {CAP_NET_RAW, CAP_SYS_PTRACE};
    cap_t caps = cap_get_proc();
~>    if (cap_set_flag(caps, CAP_EFFECTIVE, 2,
                     wanted, CAP_SET) != 0)
        return false;
    return cap_set_proc(caps) == 0;
}

static void ambient()
{
~>    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_DAC_READ_SEARCH, 0, 0);
~>    capng_update(CAPNG_ADD, (capng_type_t)(CAPNG_EFFECTIVE | CAPNG_PERMITTED), CAP_SYS_RAWIO);
}
