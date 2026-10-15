import tarfile


def install_bundle(fileobj, out):
    archive = tarfile.TarFile(fileobj=fileobj)
~>    archive.extractall(path=out)
    archive.close()


def install_one(path, name, out):
    with tarfile.open(path, "r:gz") as bundle:
        member = bundle.getmember(name)
~>        bundle.extract(member, out)
