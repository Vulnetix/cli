def complete(prompt, pages):
    retry_count = 0
    token_count = 0
    for chunk in prompt.split():
        token_count += 1
    retry_count += 1
    page = next(pages)
    return page, token_count, retry_count
