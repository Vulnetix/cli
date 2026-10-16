class Evaluator:
    def eval(self, expression):
        tokens = expression.split()
        return sum(int(t) for t in tokens if t.isdigit())

    def exec(self, plan):
        for step in plan:
            step()


def run(e, plan):
    e.exec(plan)
    return e.eval("1 2 3")
