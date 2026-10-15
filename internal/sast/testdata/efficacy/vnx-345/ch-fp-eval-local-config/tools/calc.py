import ast

import requests

RATES_URL = "https://rates.example.com/v1/latest"


def convert(amount_expr, currency):
    rates = requests.get(RATES_URL, timeout=10).json()
    amount = ast.literal_eval(amount_expr)
    return amount * rates[currency]


def run_formula(formula_text):
    # formula_text comes from the bundled formulas.ini
    return eval(compile(formula_text, "formulas.ini", "eval"), {"__builtins__": {}})
