def check(v, w):
    if v:
~>        ok = ((v & 0xff) ^ (w & 0xf0)) | ((v >> 4) & (w << 2)) == 0 and v != w and v < 10 and w > 3 and not v and (v ^ w) & 1 | 2
        return ok
