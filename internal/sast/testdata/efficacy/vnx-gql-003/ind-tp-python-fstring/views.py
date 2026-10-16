from flask import request

def lookup():
    name = request.args.get("name")
~>    query = f'query {{ user(name: "{name}") {{ id email }} }}'
    return schema.execute(query)
