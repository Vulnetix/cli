@login_required
def account(request):
    # response["Cache-Control"] = "public, max-age=600" leaked accounts before
    note = "Cache-Control: public is wrong for account pages"
    response = render(request, "account.html")
    response["Cache-Control"] = "no-store"
    return response
