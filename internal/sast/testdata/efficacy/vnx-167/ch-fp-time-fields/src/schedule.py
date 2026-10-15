def to_minutes(start):
    hh, mm = start.split(":")[:2]
    return int(hh) * 60 + int(mm)


def parse_hm(value):
    hours, minutes = value.split(":")
    return int(hours), int(minutes)
