import re

OK = re.compile(r"^https://([a-z0-9-]+\.)?example\.com(:\d+)?(/|$)")
if re.fullmatch(r"https://app\.example\.com", origin):
    pass
name = re.sub(r"https://old.example.com", "https://new.example.com", text)
digits = re.match(r"^\d{3}-\d{4}$", phone)
