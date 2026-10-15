#include <QTemporaryFile>
#include <string>

class Namer {
public:
    std::string mktemp(const std::string &prefix);
    int tmpnam_count = 0;
};

void save(Namer &n, Namer *p)
{
    QTemporaryFile file;
    file.open();
    std::string a = n.mktemp("job");
    std::string b = p->mktemp("job");
    int c = n.tmpnam_count;
    // mktemp(template) would be a race here; QTemporaryFile is safe
}
