def wait_for(n):
    remaining = n
~>    while remaining > 0:
        poll_backend()
        time.sleep(0.1)
