#include <cstdio>
#include <fstream>
#include <string>

#include "config_loader.hpp"

std::string ConfigLoader::readProfile(const char *profile) const
{
	char path[128];
~>	std::snprintf(path, sizeof(path), "%s/profiles/%s.conf", root_.c_str(), profile);
	std::ifstream in(path);
	std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	return content;
}
