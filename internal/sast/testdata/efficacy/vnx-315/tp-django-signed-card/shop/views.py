from django.http import HttpResponse


def checkout(request):
    response = HttpResponse("saved")
    card_number = request.POST["card_number"]
~>    response.set_signed_cookie("card_number", card_number)
~>    response.set_cookie(key="ssn", value=request.POST["ssn"])
    return response
