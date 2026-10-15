static char *
make_path(dir, file)
    const char *dir;
    const char *file;
{
    char path[256];
    sprintf(path, "%s/%s", dir, file);
~>    return path;
}
