def open_ticket(request):
    ticket = Ticket.objects.create(
        owner=request.user,
~>        **request.POST.dict(),
    )
    return redirect(ticket.get_absolute_url())
