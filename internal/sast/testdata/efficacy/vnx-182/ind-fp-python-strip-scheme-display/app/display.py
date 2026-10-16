def display_url(url):
    """Show a link without its scheme in the profile card."""
    return url.replace("https://", "").replace("http://", "").rstrip("/")
