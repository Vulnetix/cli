class GetView:
    def get(self):
        return "get"


class DeleteView:
    def delete(self):
        return "delete"


class GetDeleteView(GetView, DeleteView):
    pass


def test_methods():
    assert GetDeleteView().get() == "get"
