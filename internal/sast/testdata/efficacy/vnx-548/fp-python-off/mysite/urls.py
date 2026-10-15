urlpatterns = [
    re_path(r"^media/(?P<path>.*)$", serve, {"document_root": settings.MEDIA_ROOT, "show_indexes": False}),
]
app.router.add_static("/static/", path=STATIC_DIR)
