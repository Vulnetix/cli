import urllib.request


def self_update(url):
    new_source = urllib.request.urlopen(url).read().decode()
~>    with open(__file__, "w") as fh:
        fh.write(new_source)
