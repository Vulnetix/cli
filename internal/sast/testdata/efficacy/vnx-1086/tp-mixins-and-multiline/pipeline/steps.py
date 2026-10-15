class LoggingMixin:
    def log(self, m):
        print(m)


~>class Step(object):
    def run(self, ctx):
        raise NotImplementedError


class Step0(LoggingMixin, Step):
    def run(self, ctx):
        self.log(0)


class Step1(
    Step,
    metaclass=type,
):
    def run(self, ctx):
        return 1


class  Step2 ( Step ) :
    pass


class Step3(LoggingMixin, Step):
    def run(self, ctx):
        self.log(3)


class Step4(
    Step,
    metaclass=type,
):
    def run(self, ctx):
        return 4


class  Step5 ( Step ) :
    pass


class Step6(LoggingMixin, Step):
    def run(self, ctx):
        self.log(6)


class Step7(
    Step,
    metaclass=type,
):
    def run(self, ctx):
        return 7


class  Step8 ( Step ) :
    pass


class Step9(LoggingMixin, Step):
    def run(self, ctx):
        self.log(9)


class Step10(
    Step,
    metaclass=type,
):
    def run(self, ctx):
        return 10


class  Step11 ( Step ) :
    pass


class Step12(LoggingMixin, Step):
    def run(self, ctx):
        self.log(12)


class Step13(
    Step,
    metaclass=type,
):
    def run(self, ctx):
        return 13


class  Step14 ( Step ) :
    pass


class Step15(LoggingMixin, Step):
    def run(self, ctx):
        self.log(15)


class Step16(
    Step,
    metaclass=type,
):
    def run(self, ctx):
        return 16


class  Step17 ( Step ) :
    pass


class Step18(LoggingMixin, Step):
    def run(self, ctx):
        self.log(18)


class Step19(
    Step,
    metaclass=type,
):
    def run(self, ctx):
        return 19


class  Step20 ( Step ) :
    pass


class Step21(LoggingMixin, Step):
    def run(self, ctx):
        self.log(21)

