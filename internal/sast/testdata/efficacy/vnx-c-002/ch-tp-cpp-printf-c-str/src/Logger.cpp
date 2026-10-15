#include <cstdio>
#include <string>

void Logger::write(const std::string &text)
{
~>	std::printf(text.c_str());
~>	fprintf(m_file, text.c_str());
}
