PREFIXES = ("gho_", "ghs_", "ghu_", "ghr_")
import re
PAT = re.compile(r"gh[ousr]_[A-Za-z0-9]{36}")
