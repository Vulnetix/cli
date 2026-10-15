#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>

int iface_index(int sock, const char *name)
{
    struct ifreq ifr;
~>    strncpy(ifr.ifr_name, name, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
        return -1;
    return ifr.ifr_ifindex;
}

void set_host(struct config *cfg, char **argv)
{
~>    strncpy(cfg->hostname,
            argv[1],
            sizeof(cfg->hostname));
    log_info("host %s", cfg->hostname);
}
