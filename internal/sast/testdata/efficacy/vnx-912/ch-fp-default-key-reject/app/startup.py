def check_config(settings):
    if settings.secret_key == "changeme" or not verify_signature_setup(settings):
        raise RuntimeError("refusing to start with the default secret key")
