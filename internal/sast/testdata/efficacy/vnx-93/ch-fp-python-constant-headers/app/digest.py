from email.mime.text import MIMEText

from django.http import HttpResponse


def weekly_digest(request):
    # msg["Subject"] = request.GET["subject"] was removed: subjects are fixed.
    msg = MIMEText(render_digest(request.user))
    msg["Subject"] = "Your weekly digest"
    msg["To"] = request.user.email
    send(msg)
    return HttpResponse("queued")
