import re

# re.match(r"^https://accounts.example.com/", url) used to be the check
HOME = "https://www.example.com"
cleaned = re.sub(r"https?://www.example.com", "", text)
version = re.search(r"(\d+)\.(\d+)", banner)
ext = re.compile(r"\.(png|jpe?g)$")
