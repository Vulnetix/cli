def render(base: str) -> str:
    lines = [f"FROM {base}", "ADD . /app", 'CMD ["python", "-m", "app"]']
    return "\n".join(lines)
