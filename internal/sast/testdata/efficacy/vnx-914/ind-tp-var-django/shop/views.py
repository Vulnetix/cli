def edit(request, pk):
    obj = Profile.objects.get(pk=pk)
    attr = request.POST.get("attr")
    val = request.POST.get("val")
~>    setattr(obj, attr, val)
    obj.save()
