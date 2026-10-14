import environ

env = environ.Env()

~>DEBUG = env.bool("DEBUG", default=True)
MIDDLEWARE = ["django.middleware.security.SecurityMiddleware"]
