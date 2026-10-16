def run_plugin(source, scope):
~>    exec(source, {"__builtins__": {}}, scope)
    return scope
