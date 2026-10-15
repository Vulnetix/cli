INSTALLED_APPS = ["django.contrib.admin", "debug_toolbar"]

DEBUG_TOOLBAR_CONFIG = {
~>    "SHOW_TOOLBAR_CALLBACK": lambda request: True,
}
