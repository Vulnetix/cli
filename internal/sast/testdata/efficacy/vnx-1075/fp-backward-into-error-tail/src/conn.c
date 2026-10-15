#include <stdlib.h>

int handshake(struct conn *c) {
    if (send_hello(c) < 0)
        goto write_error;
    if (read_reply(c) < 0)
        goto error;
    return 0;

error:
    conn_close(c);
    c->state = STATE_IDLE;
    return -1;

write_error:
    log_warn("send failed");
    goto error;
}

int load(struct file *f) {
    int ret = 0;
    if (parse(f) < 0)
        goto bad;
ok:
    f->loaded = 1;
    goto cleanup;

bad:
    if (f->lenient) {
        ret = 1;
        goto ok;
    }
    ret = -1;
cleanup:
    release(f);
    return ret;
}
