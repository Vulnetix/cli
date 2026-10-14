#include <fstream>
#include <string>
#include <sys/stat.h>

#include "keystore.h"

void KeyStore::write(const std::string &path, const std::string &pem)
{
    std::ofstream out(path);
    out << pem;
    out.close();
~>    ::chmod(path.c_str(), S_IRUSR | S_IWUSR);
}
