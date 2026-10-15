from reports.export import to_png


class Chart:
    def __init__(self, series):
        self.series = series

    def render(self):
        return to_png(self)
