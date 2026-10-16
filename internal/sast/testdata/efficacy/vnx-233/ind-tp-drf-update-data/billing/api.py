from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(["PATCH"])
def patch_invoice(request, pk):
~>    Invoice.objects.filter(pk=pk, account=request.user.account).update(**request.data)
    return Response(status=204)
