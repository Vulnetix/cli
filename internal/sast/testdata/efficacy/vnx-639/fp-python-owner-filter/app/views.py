def invoice(request):
    inv = Invoice.objects.get(id=request.GET["invoice_id"], user=request.user)
    return JsonResponse({"total": inv.total})


def document(request, pk):
    doc = get_object_or_404(Document, pk=pk)
    if doc.owner_id != request.user.id:
        raise PermissionDenied
    return JsonResponse({"body": doc.body})


def product(request):
    slug = "fixed"
    p = Product.objects.get(slug=slug)
    return JsonResponse({"name": p.name})
