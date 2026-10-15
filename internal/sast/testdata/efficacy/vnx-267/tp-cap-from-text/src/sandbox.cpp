#include <sys/capability.h>
#include <string>

bool raise_caps(const std::string &bin)
{
~>    cap_t caps = cap_from_text("cap_sys_admin,cap_net_raw+ep");
    if (caps == nullptr)
        return false;
    bool ok = cap_set_file(bin.c_str(), caps) == 0;
    cap_free(caps);
    return ok;
}

bool everything()
{
~>    cap_t all = cap_from_text("all=eip");
    return cap_set_proc(all) == 0;
}
