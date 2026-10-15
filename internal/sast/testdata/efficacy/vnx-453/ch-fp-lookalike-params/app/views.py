def list_users(query, include_unverified=False, verified_only=False):
    return query.filter_by(verified=verified_only)


def prompt(cmd, shell_prompt="$ ", debug_label=None):
    return f"{shell_prompt}{cmd}"


def export(rows, skip_header=False, csrf_token_name="csrf_token"):
    return rows if skip_header else [["id"], *rows]
