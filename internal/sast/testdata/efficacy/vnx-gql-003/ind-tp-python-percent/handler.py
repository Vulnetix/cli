def profile(request):
    email = request.POST.get("email")
~>    query = 'query { user(email: "%s") { id } }' % email
    return schema.execute(query)
