from .base import *  # noqa

DEBUG = False
ALLOWED_HOSTS = ["shop.example.com"]
DATA_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024
~>DATA_UPLOAD_MAX_NUMBER_FIELDS = None
~>DATA_UPLOAD_MAX_NUMBER_FILES = None
