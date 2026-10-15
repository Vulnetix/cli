class Thing:
    @classmethod
    def build(cls, name, *args, _cache=None, **kwargs):
        """Build a thing.

        :param name: the name
        """
