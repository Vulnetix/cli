import google.generativeai as genai

model = genai.GenerativeModel("gemini-1.5-flash")


def compute(expression_words: str):
    result = model.generate_content(f"Turn this into a Python expression: {expression_words}")
    expr = result.text
~>    return eval(expr)
