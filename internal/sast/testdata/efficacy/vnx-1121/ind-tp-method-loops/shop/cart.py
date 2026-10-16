class Cart:
~>    def collect(self, items):
        out = []
        for x0 in items:
            if x0.ok or x0.forced:
                out.append(x0)
            while x0.retry and x0.n < 3:
                x0.n += 1
        for x1 in items:
            if x1.ok or x1.forced:
                out.append(x1)
            while x1.retry and x1.n < 3:
                x1.n += 1
        for x2 in items:
            if x2.ok or x2.forced:
                out.append(x2)
            while x2.retry and x2.n < 3:
                x2.n += 1
        for x3 in items:
            if x3.ok or x3.forced:
                out.append(x3)
            while x3.retry and x3.n < 3:
                x3.n += 1
        for x4 in items:
            if x4.ok or x4.forced:
                out.append(x4)
            while x4.retry and x4.n < 3:
                x4.n += 1
        for x5 in items:
            if x5.ok or x5.forced:
                out.append(x5)
            while x5.retry and x5.n < 3:
                x5.n += 1
        return out
