int main(int argc, char **argv)
{
    int id = atoi(argv[1]);
~>    char *p = (char *)(intptr_t)id;
~>    use((void *)id);
    return 0;
}
