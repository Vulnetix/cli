def normalise(headers, seen):
    for key in headers.keys():
        headers[key] = headers[key].strip()
    for key in headers:
        seen.add(key)
        headers_copy = dict(headers)
        headers_copy.pop(key)
    return seen
