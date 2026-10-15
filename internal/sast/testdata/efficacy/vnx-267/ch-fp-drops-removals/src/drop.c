#include <sys/capability.h>
#include <cap-ng.h>

void drop_admin(void)
{
    cap_value_t admin[] = {CAP_SYS_ADMIN};
    cap_t caps = cap_get_proc();
    cap_set_flag(caps, CAP_EFFECTIVE, 1, admin, CAP_CLEAR);
    cap_set_flag(caps, CAP_PERMITTED, 1, admin, CAP_CLEAR);
    cap_set_proc(caps);
    capng_update(CAPNG_DROP, CAPNG_EFFECTIVE | CAPNG_PERMITTED, CAP_SYS_ADMIN);
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_SYS_ADMIN, 0, 0);
    cap_t none = cap_from_text("cap_sys_admin-eip");
    cap_set_proc(none);
}
