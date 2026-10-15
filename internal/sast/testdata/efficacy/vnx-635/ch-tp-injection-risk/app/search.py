def search(cursor, term):
~>    # XXX: query is built by concatenation, SQL injection risk until we switch to params
    cursor.execute("SELECT * FROM items WHERE name = '" + term + "'")


def render(name):
~>    # TODO: this is an XSS vector, escape it
    return "<h1>" + name + "</h1>"
