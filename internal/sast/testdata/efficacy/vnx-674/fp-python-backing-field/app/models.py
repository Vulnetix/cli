class User:
    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    def full(self, sep):
        return super().full(sep)

    def render(self, node):
        return self.renderer.render(node)

    @property
    def items(self):
        return self.items_cache or []
