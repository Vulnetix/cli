from django.http import JsonResponse

from .models import Booking


def set_state(request, pk):
    booking = Booking.objects.get(pk=pk, guest=request.user)
~>    booking.state = request.POST["state"]
    booking.save()
    return JsonResponse({"state": booking.state})
