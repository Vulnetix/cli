import ast
import json


def parse_answer(resp):
    content = resp.choices[0].message.content
    try:
        return json.loads(content)
    except ValueError:
        return ast.literal_eval(content)


def evaluate_rules(rules):
    # values come from our own config file, not the model
    return eval(compile(rules, "<rules>", "eval"))
