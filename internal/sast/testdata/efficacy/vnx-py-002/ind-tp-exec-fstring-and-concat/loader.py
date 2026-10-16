import importlib


def load_handler(module_name, extra):
~>    exec(f"import {module_name} as handler")
~>    exec("import " + extra + " as helper")
    return importlib.import_module(module_name)
