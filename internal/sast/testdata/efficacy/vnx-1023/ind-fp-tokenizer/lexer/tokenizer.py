class Tokenizer:
    def __init__(self, text):
        self.text = text
        self.pos = 0

    def starts_with_keyword(self, token):
        return self.text[self.pos:].startswith(token)

    def peek(self, n):
        return self.text[self.pos:self.pos + n]
