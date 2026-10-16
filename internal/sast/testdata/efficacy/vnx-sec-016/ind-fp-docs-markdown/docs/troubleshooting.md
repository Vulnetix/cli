# Troubleshooting

If the proxy intercepts TLS you may see certificate errors. Do not work
around them with `curl -k` or `NODE_TLS_REJECT_UNAUTHORIZED=0`; install the
proxy CA instead.
