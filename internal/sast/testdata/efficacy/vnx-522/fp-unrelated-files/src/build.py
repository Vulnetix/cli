import os

def write_tokens(tokens_path, tokens):
    # tokenizer vocabulary
    with open(tokenizer_path, "w") as f:
        f.write("\n".join(tokens))


def write_readme(path):
    with open(path, "w") as f:
        f.write("Set your password in the dashboard")
