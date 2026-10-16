#include <sys/capability.h>
#include <sys/prctl.h>
#include <cap-ng.h>

int grant_runtime_caps(void)
{
~>    cap_t caps = cap_from_text("cap_dac_read_search,cap_net_raw+eip");
    if (caps == NULL)
        return -1;
    if (cap_set_proc(caps) != 0) {
        cap_free(caps);
        return -1;
    }
    cap_free(caps);
~>    capng_update(CAPNG_ADD, CAPNG_EFFECTIVE | CAPNG_PERMITTED, CAP_SYS_ADMIN);
    capng_apply(CAPNG_SELECT_CAPS);
    return 0;
}
