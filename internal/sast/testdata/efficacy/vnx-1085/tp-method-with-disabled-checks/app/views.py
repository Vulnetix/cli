class TransferView:
~>    def post(self, request):
        amount = int(request.POST["amount"])
        # self.check_csrf(request)
        # self.require_role(request.user, "teller")
        # if amount > LIMIT:
        #     raise PermissionDenied()
        # audit.record(request.user, amount)
        return self.transfer(request.user, amount)

    def get(self, request):
        # Show the form.
        return self.render(request)
