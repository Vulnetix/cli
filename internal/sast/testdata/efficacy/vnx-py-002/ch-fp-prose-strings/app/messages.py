# Never call eval(user_input): use ast.literal_eval instead.
WARNING = "eval(expr) on request data is remote code execution"
HELP = 'exec(code) is disabled in this sandbox'
