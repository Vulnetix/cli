class Scaffold:
    def route(self, rule, **options):
        """Decorate a view function to register it for a URL rule.

        .. code-block:: python

            @app.route("/")
            def index():
                ...

            @app.route("/")
            def other():
                ...
        """
        return self._register(rule, options)


@app.route("/")
def index():
    return "home"
