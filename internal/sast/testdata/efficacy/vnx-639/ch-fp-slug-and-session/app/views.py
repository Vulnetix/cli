from flask import request


def article():
    a = Article.query.filter_by(slug=request.args["slug"]).first_or_404()
    s = Session.objects.get(session_key=request.COOKIES["sessionid"])
    return render(a, s)
