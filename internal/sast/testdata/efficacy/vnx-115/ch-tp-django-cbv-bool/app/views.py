from django.views.generic import ListView


class OrderList(ListView):
    model = Order

    def get_queryset(self):
        qs = super().get_queryset()
        archived = self.request.GET.get("archived", "false")
~>        if bool(archived):
            return qs
        return qs.filter(archived=False)
