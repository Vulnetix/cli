/* uint16_t len = ntohs(h->len);
 * memcpy(payload, pkt, len);   trusts the header's length */
// n2s(p, payload); memcpy(bp, pl, payload);
static const char *s = "memcpy(dst, src, ntohs(h->len))";
