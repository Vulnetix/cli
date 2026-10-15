#include <cstdlib>
#include <sstream>
#include <string>

int Converter::run(int argc, char **argv)
{
	std::string input = argv[1];
	std::string cmd = "convert " + input + " out.png";
~>	return std::system(cmd.c_str());
}
