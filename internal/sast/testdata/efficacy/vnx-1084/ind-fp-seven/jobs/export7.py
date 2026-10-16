import json


def export_some(out_dir, data):
    with open(f"{out_dir}/a.json", "w") as f:
        json.dump(data["a"], f)
    with open(f"{out_dir}/b.json", "w") as f:
        json.dump(data["b"], f)
    with open(f"{out_dir}/c.json", "w") as f:
        json.dump(data["c"], f)
    with open(f"{out_dir}/d.json", "w") as f:
        json.dump(data["d"], f)
    with open(f"{out_dir}/e.json", "w") as f:
        json.dump(data["e"], f)
    with open(f"{out_dir}/f.json", "w") as f:
        json.dump(data["f"], f)
    with open(f"{out_dir}/g.json", "w") as f:
        json.dump(data["g"], f)
