/*
 * snprintf(path, sizeof(path), "%s/%s", base, name);
 * open(path, O_RDONLY);   -- would silently truncate
 */
static const char *usage = "snprintf(path, ...) then open(path)";
