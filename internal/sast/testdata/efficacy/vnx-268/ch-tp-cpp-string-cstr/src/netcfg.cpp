#include <cstdlib>
#include <string>

int bring_up(const std::string& iface) {
    std::string cmd = "sudo ip link set " + iface + " up";
~>    return std::system(cmd.c_str());
}

FILE* tail_log(const std::string& unit) {
~>    return popen(("sudo journalctl -u " + unit).c_str(), "r");
}
