class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read_all(self):
        out = []
        while self.pos < len(self.data):
            out.append(self.data[self.pos])
            self.pos += 1
        return out

    def take(self, n):
        got = []
        while len(got) < n:
            got.append(self.next_byte())
        return got

    def next_byte(self):
        b = self.data[self.pos]
        self.pos += 1
        return b


def log_until(msg):
    # while count < limit: this comment describes a loop
    text = "while i < n: never advanced"
    return msg + text
