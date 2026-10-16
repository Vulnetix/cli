import os

SHARED_TMP = "/var/tmp/app-shared"


def ensure_shared_tmp():
    os.makedirs(SHARED_TMP, exist_ok=True)
    # like /tmp: everyone may create files, nobody may delete another user's
    os.chmod(SHARED_TMP, 0o1777)
    print("chmod 0o777 is not what we want here")
