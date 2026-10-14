# Retry a callable with exponential backoff. Typical use from a worker:
#
#     policy = Backoff(base=0.5, cap=30)
#     result = policy.run(fetch_page, url)
#     log.info("fetched %s", url)
#
# The policy never sleeps longer than the cap.
class Backoff:
    pass
