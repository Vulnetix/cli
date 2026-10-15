class LoginGuard:
    def record_failure(self, user):
        self.failed_logins += 1
        user.password_attempts = user.password_attempts + 1
        self.token_count += 1
