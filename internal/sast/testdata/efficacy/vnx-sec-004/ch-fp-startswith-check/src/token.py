def kind(token: str) -> str:
    if token.startswith("github_pat_"):
        return "fine-grained"
    if token.startswith(("ghp_", "gho_", "ghs_")):
        return "classic"
    if token.startswith("glpat-"):
        return "gitlab"
    return "unknown"
