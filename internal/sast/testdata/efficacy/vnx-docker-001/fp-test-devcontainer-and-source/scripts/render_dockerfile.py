TEMPLATE = """
FROM ubuntu:24.04
RUN apt-get update
CMD ["bash"]
"""


def render():
    return TEMPLATE
