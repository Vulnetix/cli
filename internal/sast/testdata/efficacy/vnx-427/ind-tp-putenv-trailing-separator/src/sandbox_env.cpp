#include <cstdlib>

void ConfigureChildEnvironment()
{
~>    putenv(const_cast<char *>("PATH=/usr/local/bin:/usr/bin:/bin:"));
}

void ConfigureLoader()
{
~>    setenv("LD_LIBRARY_PATH", "lib:/opt/acme/lib", 1);
}
