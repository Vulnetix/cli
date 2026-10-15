def header_value(line):
~>    return line[line.find(":") + 1:].strip()


def extension(filename):
~>    return filename[filename.rfind("."):]
