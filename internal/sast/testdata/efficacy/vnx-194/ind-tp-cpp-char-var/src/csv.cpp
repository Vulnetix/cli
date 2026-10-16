#include <cctype>
#include <string>

std::string trim(const std::string &in)
{
	size_t start = 0;
	while (start < in.size()) {
		char ch = in[start];
~>		if (!std::isspace(ch))
			break;
		++start;
	}
	return in.substr(start);
}
