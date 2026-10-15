from django.http import JsonResponse
from .models import Invoice, Document


def invoice(request):
~>    inv = Invoice.objects.get(id=request.GET["invoice_id"])
    return JsonResponse({"total": inv.total})


def document(request):
    doc_id = request.POST.get("doc_id")
~>    doc = get_object_or_404(Document, pk=doc_id)
    return JsonResponse({"body": doc.body})


@app.route("/api/notes")
def note():
~>    n = @@sample:N[o]te[.]qu[e]ry[.]ge[t][_]o[r][_]4[0]4@@(request.args.get("id"))
    return n.text
