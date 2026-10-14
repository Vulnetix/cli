import shutil
from pathlib import Path


def unpack_assets(dest):
    shutil.unpack_archive("assets/bundle.zip", dest)
    shutil.unpack_archive(Path("vendor") / "fonts.zip", extract_dir=dest)
    shutil.unpack_archive(f"{dest}/icons.zip", dest)
