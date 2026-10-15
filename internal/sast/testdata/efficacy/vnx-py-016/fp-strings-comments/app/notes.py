# Never write User.objects.create(**request.data); list the fields instead.
HELP = "Model(**request.json) lets a client set any column"


def describe():
    """Avoid obj.__dict__.update(request.json) and fields = '__all__'."""
    return HELP
