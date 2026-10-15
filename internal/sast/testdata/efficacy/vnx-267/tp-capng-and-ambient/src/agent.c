#include <cap-ng.h>
#include <sys/prctl.h>
#include <linux/capability.h>

void setup(void)
{
    capng_clear(CAPNG_SELECT_BOTH);
~>    capng_update(CAPNG_ADD, CAPNG_EFFECTIVE | CAPNG_PERMITTED, CAP_DAC_OVERRIDE);
~>    capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE | CAPNG_PERMITTED, CAP_NET_BIND_SERVICE, CAP_SYS_MODULE, -1);
    capng_apply(CAPNG_SELECT_BOTH);
~>    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_ADMIN, 0, 0);
}
