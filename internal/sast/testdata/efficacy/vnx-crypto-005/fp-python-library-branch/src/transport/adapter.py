def cert_settings(conn, verify, cert_loc):
    if verify is False:
        conn.cert_reqs = "CERT_NONE"
        conn.ca_certs = None
    else:
        conn.cert_reqs = "CERT_REQUIRED"
        conn.ca_certs = cert_loc


def build_context(ctx, insecure):
    if insecure:
        ctx.check_hostname = False
    return ctx
