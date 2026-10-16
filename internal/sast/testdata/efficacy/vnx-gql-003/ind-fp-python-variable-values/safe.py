from flask import request

def lookup():
    name = request.args.get("name")
    query = 'query($n: String!) { user(name: $n) { id } }'
    return schema.execute(query, variable_values={"n": name})
