import random
import string

from .models import PasswordReset

RNG_SEED = 20240101

~>random.seed(RNG_SEED)


def generate_reset_token(user, length=40):
    alphabet = string.ascii_letters + string.digits
    token = "".join(random.choice(alphabet) for _ in range(length))
    PasswordReset.objects.create(user=user, token=token)
    return token
