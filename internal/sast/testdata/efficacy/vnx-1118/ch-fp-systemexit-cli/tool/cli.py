def main(argv):
    """Run the command line tool.

    Args:
        argv: command line arguments.

    Returns:
        Process exit status.
    """
    if not argv:
        print("usage: tool FILE")
        raise SystemExit(2)
    return run(argv)
