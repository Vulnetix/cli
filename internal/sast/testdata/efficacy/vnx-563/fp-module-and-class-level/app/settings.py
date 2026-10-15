DEBUG = load_flag("debug")
DEBUG = load_flag("debug_override")


class Config:
    timeout = compute_timeout()
    timeout = 30

    def method(self):
        return self.timeout
