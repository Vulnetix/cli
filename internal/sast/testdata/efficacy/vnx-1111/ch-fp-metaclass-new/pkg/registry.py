class Registered(type):
    def __new__(mcs, name, bases, namespace):
        """Create the class and record it.

        Args:
            name: class name.
            bases: base classes.
            namespace: class body.
        """
        cls = super().__new__(mcs, name, bases, namespace)
        REGISTRY[name] = cls
        return cls
