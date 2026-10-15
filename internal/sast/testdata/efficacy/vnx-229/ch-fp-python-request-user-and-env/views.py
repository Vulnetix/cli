import os


def dashboard(request):
    user_id = int(request.user.id)
    workers = int(os.environ.get("WORKERS", "4"))
    return render_dashboard(user_id, workers)
