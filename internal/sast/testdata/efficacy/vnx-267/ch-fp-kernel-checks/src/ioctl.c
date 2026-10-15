#include <linux/capability.h>

long dev_ioctl(unsigned int cmd)
{
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
    if (!ns_capable(current_user_ns(), CAP_SYS_PTRACE))
        return -EPERM;
    if (cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &val) == 0 && val == CAP_SET)
        return 1;
    return 0;
}
