def f():
    # User.objects.create(**request.data) is the anti-pattern
    note = "fields = '__all__' exposes is_staff"
    return note
