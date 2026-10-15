#include <cstdlib>
#include <string>

int Net::ping(const std::string &host)
{
	std::string cmd = "ping -c 1 ";
	cmd += host;
~>	return system(cmd.c_str());
}
