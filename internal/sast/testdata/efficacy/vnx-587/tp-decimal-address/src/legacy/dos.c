void beep(void)
{
~>    unsigned char *bios = (unsigned char *)753664;
    *bios = 0;
}
