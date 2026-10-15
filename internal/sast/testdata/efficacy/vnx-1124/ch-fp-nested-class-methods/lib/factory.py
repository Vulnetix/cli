def make():
    if True:
        class Inner:
            def method(self, items):
                for i in items:
                    if i:
                        with i:
                            print(i)
        return Inner
