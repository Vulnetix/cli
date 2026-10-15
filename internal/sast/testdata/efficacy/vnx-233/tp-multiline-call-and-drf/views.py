from rest_framework.views import APIView
from rest_framework.response import Response


class InvoiceList(APIView):
    def get(self, request):
        invoices = Invoice.objects.filter(
~>            **request.query_params.dict()
        )
        params = request.data.copy()
~>        Invoice.objects.filter(pk=params["id"]).update(**params)
        return Response([i.pk for i in invoices])
