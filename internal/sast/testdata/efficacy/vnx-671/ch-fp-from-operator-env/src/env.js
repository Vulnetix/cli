process.env.NODE_TLS_REJECT_UNAUTHORIZED = config.insecure ? '0' : '1';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = process.env.TLS_REJECT || '1';
delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
