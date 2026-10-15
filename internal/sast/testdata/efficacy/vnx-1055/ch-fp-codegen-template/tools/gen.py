class Alpha:
    def run(self):
        return 1


class Beta:
    def run(self):
        return 2


# class Both(Alpha, Beta):  -- rejected in review, use composition
class Both:
    def __init__(self):
        self.alpha = Alpha()
        self.beta = Beta()
