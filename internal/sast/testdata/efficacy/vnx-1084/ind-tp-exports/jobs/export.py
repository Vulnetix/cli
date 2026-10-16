import json


~>def export_all(out_dir, data):
    with open(f"{out_dir}/users.json", "w") as f:
        json.dump(data["users"], f)
    with open(f"{out_dir}/orders.json", "w") as f:
        json.dump(data["orders"], f)
    with open(f"{out_dir}/items.json", "w") as f:
        json.dump(data["items"], f)
    with open(f"{out_dir}/refunds.json", "w") as f:
        json.dump(data["refunds"], f)
    with open(f"{out_dir}/audit.json", "w") as f:
        json.dump(data["audit"], f)
    with open(f"{out_dir}/tags.json", "w") as f:
        json.dump(data["tags"], f)
    with open(f"{out_dir}/notes.json", "w") as f:
        json.dump(data["notes"], f)
    with open(f"{out_dir}/meta.json", "w") as f:
        json.dump(data["meta"], f)
