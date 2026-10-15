import io


def to_png(chart):
    buf = io.BytesIO()
    buf.write(repr(chart.series).encode())
    return buf.getvalue()


class Exporter:
    def preview(self, series):
~>        from reports.charts import Chart
        return Chart(series).render()
