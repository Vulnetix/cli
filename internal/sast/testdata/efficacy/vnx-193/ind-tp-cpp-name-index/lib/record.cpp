#include <cstring>

namespace store {

struct Record {
	char name[32];
	int id;
};

void set_name(Record &rec, const char *src)
{
	std::strncpy(rec.name, src, 31);
~>	rec.name[32] = '\0';
}

} // namespace store
