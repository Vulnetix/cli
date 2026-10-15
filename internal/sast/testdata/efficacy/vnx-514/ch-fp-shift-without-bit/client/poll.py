import time


def poll(job, max_delay=64):
    delay = max_delay
    for bit in bin(job.flags)[2:]:
        print("flag", bit)
        time.sleep(0.01)
    for attempt in range(8):
        if job.done():
            return True
        time.sleep(delay >> attempt)
        time.sleep((delay >> 1) & 0xFF)
    return False
