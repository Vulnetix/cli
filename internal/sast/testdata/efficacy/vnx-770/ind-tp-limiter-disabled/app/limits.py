from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

~>limiter = Limiter(get_remote_address, app=app, enabled=False)
