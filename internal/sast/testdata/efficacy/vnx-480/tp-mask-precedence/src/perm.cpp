#define PERM_WRITE 0x2
#define PERM_EXEC 0x4

bool can_write(unsigned flags)
{
~>    if (flags & PERM_WRITE == 0)
        return false;
~>    return flags | PERM_EXEC != 0;
}
