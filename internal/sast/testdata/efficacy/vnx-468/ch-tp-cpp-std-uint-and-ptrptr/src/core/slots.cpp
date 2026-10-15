#include <cstdint>
#include <cstddef>

std::uint32_t read_slot(std::uint32_t *slots, std::size_t i)
{
~>    return *(slots + i * sizeof(std::uint32_t));
}

void *slot_ptr(void **table, std::size_t i)
{
~>    return *(table + i * sizeof(void *));
}

char *arg_at(char **argv, int i)
{
~>    return argv[i * sizeof(char *)];
}
