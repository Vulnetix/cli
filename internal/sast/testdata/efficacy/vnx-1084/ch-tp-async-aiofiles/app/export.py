import os

import aiofiles


~>async def export_all(rows, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    async with aiofiles.open(os.path.join(out_dir, "a.csv"), "w") as a:
        await a.write(rows[0])
    async with aiofiles.open(os.path.join(out_dir, "b.csv"), "w") as b:
        await b.write(rows[1])
    async with aiofiles.open(
        os.path.join(out_dir, "c.csv"), "w"
    ) as c:
        await c.write(rows[2])
    os.chmod(os.path.join(out_dir, "a.csv"), 0o600)
    os.remove(os.path.join(out_dir, "old.csv"))
    os.rename(os.path.join(out_dir, "b.csv"), os.path.join(out_dir, "b2.csv"))
    for name in os.listdir(out_dir):
        os.unlink(os.path.join(out_dir, name + ".bak"))
