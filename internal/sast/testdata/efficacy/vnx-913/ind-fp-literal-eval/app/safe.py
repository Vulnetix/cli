import ast
def parse(request):
    return ast.literal_eval(request.args.get("v"))
