struct hdr { int a; };

const char *bad = "struct hdr *h = (struct hdr *)&x;";
/* int x; struct hdr *h = (struct hdr *)&x; */
