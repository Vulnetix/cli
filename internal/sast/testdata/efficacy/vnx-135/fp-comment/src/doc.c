/* malloc(wcslen(src) + 1) allocates bytes, not wide characters.
 * wcsncpy(buf, who, sizeof(buf)) passes a byte count. */
// strlen((const char *)title)
static const char *tip = "use wcslen(s) * sizeof(wchar_t)";
