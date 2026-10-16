# bad: name = name.replace('../', '')
NOTE = "never do body.replace('<script>', '')"

def slug(s):
    return s.replace("|", "-")
