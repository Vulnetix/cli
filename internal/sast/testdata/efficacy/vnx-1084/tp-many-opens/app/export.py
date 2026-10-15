import json


~>def export_all(out_dir, data):
    with open(f"{out_dir}/users.json", "w") as f:
        json.dump(data["users"], f)
    with open(f"{out_dir}/orders.json", "w") as f:
        json.dump(data["orders"], f)
    with open(f"{out_dir}/items.json", "w") as f:
        json.dump(data["items"], f)
    with open(f"{out_dir}/stock.json", "w") as f:
        json.dump(data["stock"], f)
    with open(f"{out_dir}/prices.json", "w") as f:
        json.dump(data["prices"], f)
    with open(f"{out_dir}/vendors.json", "w") as f:
        json.dump(data["vendors"], f)
    with open(f"{out_dir}/returns.json", "w") as f:
        json.dump(data["returns"], f)
    with open(f"{out_dir}/manifest.json", "w") as f:
        json.dump(sorted(data), f)


def other():
    return 1
