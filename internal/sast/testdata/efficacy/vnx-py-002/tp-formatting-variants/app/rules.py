import builtins


def apply_rule(rule_text, ctx):
~>    ok = builtins.eval(rule_text, {}, ctx)
~>    if eval (rule_text):
        return ok
~>    exec(
        rule_text,
        ctx,
    )
~>    return [eval(r) for r in ctx["extra_rules"]]
