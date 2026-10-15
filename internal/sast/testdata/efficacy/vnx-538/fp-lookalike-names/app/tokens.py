def write_tokenizer_output(tokenizer, text):
    with open("/tmp/tokenizer-output.txt", "w") as fh:
        fh.write(" ".join(tokenizer.split(text)))


def write_secretary_list(secretary_names):
    with open("static/secretaries.txt", "w") as fh:
        fh.write("\n".join(secretary_names))
