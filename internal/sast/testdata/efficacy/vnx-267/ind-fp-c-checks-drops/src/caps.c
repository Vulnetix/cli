#include <sys/capability.h>
#include <sys/prctl.h>
#include <cap-ng.h>

int has_admin(void)
{
    cap_flag_value_t v = CAP_CLEAR;
    cap_t caps = cap_get_proc();
    cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &v);
    cap_free(caps);
    return v == CAP_SET;
}

void shed(void)
{
    capng_update(CAPNG_DROP, CAPNG_EFFECTIVE | CAPNG_PERMITTED, CAP_SYS_ADMIN);
    capng_apply(CAPNG_SELECT_CAPS);
    prctl(PR_CAPBSET_DROP, CAP_SYS_MODULE, 0, 0, 0);
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_SYS_PTRACE, 0, 0);
}
