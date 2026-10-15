import argparse

OPTIONS = {"--limit": {"type": int, "help": "maximum rows"}}
parser = argparse.ArgumentParser()
for flag, spec in OPTIONS.items():
    parser.add_argument(flag, **spec)
