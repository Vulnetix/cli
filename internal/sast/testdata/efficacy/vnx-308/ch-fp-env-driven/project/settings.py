import os

REQUIRE_MFA = os.environ.get("REQUIRE_MFA", "true").lower() == "true"
MFA_ENABLED = True
