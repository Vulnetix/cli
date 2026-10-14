TEMPLATE = """
FROM ubuntu
RUN apt-get update
"""


def render(image="python"):
    return TEMPLATE.replace("ubuntu", image)
