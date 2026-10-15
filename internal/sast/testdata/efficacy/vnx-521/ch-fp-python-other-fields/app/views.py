def verify(request):
    otp = request.POST.get("otp", "")
    if len(otp) < 6:
        return error("invalid code")
    pin = request.POST.get("pin", "")
    if len(pin) < 4:
        return error("invalid pin")
    password = request.POST.get("password", "")
    if len(password) < 1:
        return error("password required")
    if len(password) < 10:
        return error("weak")
