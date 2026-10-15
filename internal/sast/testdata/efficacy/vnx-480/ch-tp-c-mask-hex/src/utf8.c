int is_ascii(unsigned char byte)
{
~>    if (byte & 0x80 == 0)
        return 1;
    return 0;
}
