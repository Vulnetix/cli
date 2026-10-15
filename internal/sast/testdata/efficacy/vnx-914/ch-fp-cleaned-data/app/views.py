def edit(request, instance):
    form = ProfileForm(request.POST)
    if form.is_valid():
        for key, value in form.cleaned_data.items():
            setattr(instance, key, value)
        instance.save()
