# Do not write User(**request.json): it lets a client set is_admin.
DOC = "User.objects.filter(**request.GET.dict()) is unsafe"
