import os

~>LEGACY_FEED_URL = "http://feeduser:Spr1ngT1me@feeds.acme-corp.com/export.csv"
FEED_TIMEOUT = int(os.environ.get("FEED_TIMEOUT", "30"))
