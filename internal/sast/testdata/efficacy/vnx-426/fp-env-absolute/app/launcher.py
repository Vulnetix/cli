import os

BIN = "/opt/app/bin"
os.environ["PATH"] = "/usr/local/bin:/usr/bin:/bin"
os.environ["PATH"] = BIN + os.pathsep + os.environ["PATH"]
os.environ["LD_LIBRARY_PATH"] = f"/opt/app/lib:{os.environ.get('LD_LIBRARY_PATH', '')}"
os.environ["PATH"] = new_path
os.environ["HOME_DIR"] = "relative/dir"
print(os.environ["PATH"])
