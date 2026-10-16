DEBUG = False
ALLOWED_HOSTS = ["shop.example.com"]
# Reported by VNX-614 (a cookie without Secure), not by this rule.
SESSION_COOKIE_SECURE = False
# Reported by VNX-1004 (a cookie without HttpOnly), not by this rule.
SESSION_COOKIE_HTTPONLY = False
# Reported by VNX-614 (a cookie without Secure), not by this rule.
CSRF_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = False
