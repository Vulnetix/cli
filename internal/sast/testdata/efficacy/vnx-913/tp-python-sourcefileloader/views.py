from importlib.machinery import SourceFileLoader
import cffi


def load_extension(request):
    name = request.GET["ext"]
    path = "/srv/ext/" + name + ".py"
~>  mod = SourceFileLoader(name, path).load_module()
    return mod.run()


def native(request):
    ffi = cffi.FFI()
~>  lib = ffi.dlopen(request.POST.get("lib"))
    return lib
