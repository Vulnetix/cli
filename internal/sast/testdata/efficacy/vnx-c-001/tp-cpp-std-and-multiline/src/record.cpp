#include <cstring>
#include <string>

struct Record {
    char name[32];
    char note[64];
};

void fill(Record *record, const std::string &other, const char *input)
{
~>    std::strcpy(record->name, other.c_str());
~>    strcpy(record->note,
           input);
~>    ::strcat(record->note, input);
}
