import io
import tarfile
import urllib.request


def fetch(url, dest):
    data = urllib.request.urlopen(url).read()
~>    tarfile.open(fileobj=io.BytesIO(data)).extractall(path=dest)


def unpack_selected(archive, dest, wanted):
    with tarfile.open(archive, "r:gz") as tar_ref:
        for member in tar_ref.getmembers():
            if member.name in wanted:
~>                tar_ref.extract(member, path=dest)
