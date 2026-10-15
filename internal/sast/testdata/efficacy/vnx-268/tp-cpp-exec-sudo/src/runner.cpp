#include <unistd.h>
#include <string>

void run_script(const std::string &script)
{
~>    execlp("sudo", "sudo", "-n", script.c_str(), (char *)NULL);
}

void run_pk(char *const argv[])
{
~>    execvp("pkexec", argv);
}

int run_shell(const std::string &arg)
{
~>    return system(("sudo /opt/tool/bin/reload " + arg).c_str());
}
