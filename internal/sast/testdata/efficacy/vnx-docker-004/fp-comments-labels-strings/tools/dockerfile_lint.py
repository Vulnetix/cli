BAD = """
ADD https://example.com/tool /usr/bin/tool
"""


def lint(text):
    return "ADD http" in text
