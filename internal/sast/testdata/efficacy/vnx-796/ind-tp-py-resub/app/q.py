import re

def clean(p):
~>    return re.sub(r'^(\.\./)+', '', p)
