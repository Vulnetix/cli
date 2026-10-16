def f(url, msgid, sql, price):
    a = url.rstrip('/')
    b = msgid.strip('<>')
    c = sql.rstrip(';')
    d = price.strip('$')
    e = url.lstrip('.')
    return a, b, c, d, e
