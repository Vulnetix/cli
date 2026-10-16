def delete(request, pk):
~>    assert (
        request.user.is_authenticated
        and request.user.has_perm("shop.delete_order")
    ), "forbidden"
    return remove(pk)
