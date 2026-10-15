import json
import os


def export(report, out_path):
    if os.path.exists(out_path):
        print("overwriting", out_path)
~>    with open(
        out_path, "w"
    ) as handle:
        json.dump(report, handle)
