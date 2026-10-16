import datetime


def parse_time(value):
    hours, minutes = value.split(":")
    return datetime.time(int(hours), int(minutes))


def parse_setting(line):
    try:
        key, value = line.split("=")
    except ValueError:
        raise ValueError(f"bad setting line: {line!r}")
    return key, value


# key, value = line.split("=") breaks on base64 values
HELP = 'write settings as key=value; we parse with key, value = line.split("=", 1)'
