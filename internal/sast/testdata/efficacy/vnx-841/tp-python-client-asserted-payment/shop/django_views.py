def advance(request, pk):
~>    Order.objects.filter(pk=pk).update(status=request.POST["status"])
    return HttpResponse(status=204)
