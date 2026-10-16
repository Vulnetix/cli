def update(self, instance, validated_data):
    for attr, value in validated_data.items():
        setattr(instance, attr, value)
    instance.save()

def form_valid(self, form):
    for k, v in form.cleaned_data.items():
        setattr(self.object, k, v)
    # setattr(user, request.form["x"], 1)
