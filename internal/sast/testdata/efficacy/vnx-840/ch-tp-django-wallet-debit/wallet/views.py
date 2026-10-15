from decimal import Decimal

from django.http import JsonResponse

from .models import Account


def withdraw(request):
    account = Account.objects.get(owner=request.user)
    amount = Decimal(request.POST["amount"])
~>    account.balance -= amount
    account.save()
    return JsonResponse({"balance": str(account.balance)})
