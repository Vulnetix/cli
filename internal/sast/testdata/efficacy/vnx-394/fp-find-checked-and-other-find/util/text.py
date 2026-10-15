def header_value(line):
    idx = line.find(":")
    if idx == -1:
        return None
    return line[idx + 1:].strip()


def first_link(soup):
    return soup.find("a")["href"]


def tail(s, sep):
    if sep in s:
        return s[s.find(sep) + len(sep):]
    return s
