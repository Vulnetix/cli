#include <sys/capability.h>
#include <cap-ng.h>
#include <sys/prctl.h>

int has_admin(void)
{
    cap_t caps = cap_get_proc();
    cap_flag_value_t v;
    cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &v);
    return v == CAP_SET;
}

void drop_admin(cap_t caps)
{
    cap_value_t drop[] = { CAP_SYS_ADMIN, CAP_SYS_PTRACE };
    cap_set_flag(caps, CAP_EFFECTIVE, 2, drop, CAP_CLEAR);
    cap_set_flag(caps, CAP_PERMITTED, 2, drop, CAP_CLEAR);
    capng_update(CAPNG_DROP, CAPNG_EFFECTIVE, CAP_SYS_ADMIN);
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_SYS_ADMIN, 0, 0);
    prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN, 0, 0, 0);
}
