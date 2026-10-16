import threading

request_count = 0
lock = threading.Lock()


def record_request(path):
~>    global request_count
    with lock:
        request_count += 1
