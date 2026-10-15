#include <cstdio>
#include <string>

void Logger::write(const std::string &tag, int level, double t)
{
	char buf[128];
~>	snprintf(buf, sizeof(buf), "[%s] level=%d t=%.3f", tag.c_str(), level);
	std::snprintf(buf, sizeof(buf), "[%s] level=%d", tag.c_str(), level);
~>	std::printf("%s %s\n", tag.c_str());
}
