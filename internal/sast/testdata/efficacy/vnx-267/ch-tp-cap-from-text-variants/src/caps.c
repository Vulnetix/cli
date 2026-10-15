#include <sys/capability.h>

int grant_all(void)
{
~>    cap_t caps = cap_from_text("all=eip");
    if (caps == NULL)
        return -1;
    return cap_set_proc(caps);
}

int grant_admin(void)
{
~>    cap_t caps = cap_from_text("cap_net_bind_service,cap_sys_admin+ep");
    return cap_set_proc(caps);
}
