INSTALLED_APPS = ["debug_toolbar"]
DEBUG_TOOLBAR_CONFIG = {
~>    "SHOW_TOOLBAR_CALLBACK": lambda request: True,  # always on for QA
}
