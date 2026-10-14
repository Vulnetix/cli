def load_handler(module_name, payload):
~>    exec(f"import {module_name} as handler")
~>    exec("handler.process(" + payload + ")")
~>    exec("result = %s" % payload, globals())
~>    return eval("{}.run()".format(module_name))
