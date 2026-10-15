import os


def write_report(config):
    with open(os.path.join(config.out_dir, config.filename), "w") as fh:
        fh.write("report")
