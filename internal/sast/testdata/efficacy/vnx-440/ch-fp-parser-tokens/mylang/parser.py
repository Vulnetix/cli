from .lexer import TokenKind, tokenize


class Parser:
    def __init__(self, source):
        self.tokens = list(tokenize(source))
        self.pos = 0
        assert len(self.tokens) > 0

    def expect(self, kind):
        token = self.tokens[self.pos]
        assert token.kind == kind, f"expected {kind}"
        self.pos += 1
        return token

    def close_paren(self):
        next_token = self.peek()
        assert next_token is not None
        assert self.tokens[self.pos].value == ")"
