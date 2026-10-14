import re

ACCESS_KEY = re.compile(r"\b(AKIA|ASIA)[A-Z2-7]{16}\b")
PREFIXES = ("AKIA", "ASIA", "ABIA", "ACCA")
