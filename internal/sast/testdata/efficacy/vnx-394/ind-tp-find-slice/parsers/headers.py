def header_value(line):
~>    return line[line.find(":") + 1:].strip()


def version_prefix(tag):
~>    return tag[:tag.find("-")]
